# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

システムにログオンしている各**user**は、そのログオンセッション用の**security information**を持つ access token を保持しています。ユーザーがログオンすると、システムは access token を作成します。ユーザーの代わりに実行される**every process**は、access token のコピーを持ちます。この token は、ユーザー、ユーザーの groups、そしてユーザーの privileges を識別します。token には、現在のログオンセッションを識別する logon SID (Security Identifier) も含まれます。

この情報は `whoami /all` を実行すると確認できます
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### ローカル管理者

ローカル管理者がログインすると、**2つの access token が作成されます**: 1つは admin 権限付きで、もう1つは通常権限です。**デフォルトでは**、このユーザーが process を実行すると、**通常**（非管理者）**権限**のものが使われます。このユーザーが何かを**管理者として実行**しようとすると（例えば "Run as Administrator"）、**UAC** が許可を求めるために使われます。\
[**UAC についてもっと学びたい場合は、このページを読んでください**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

実際には、これは**非昇格の admin shell は通常 filtered token で動作する**ことを意味します。だからこそ、`whoami /groups` では、process が昇格されるまで **`BUILTIN\Administrators` が `Deny only`** と表示されることがよくあります。内部的には、Windows は **linked elevated token** (`TokenLinkedToken`) を保持し、`TokenElevationType` のようなフィールドで状態を追跡します。

### Credentials user impersonation

**他のユーザーの有効な credentials** があれば、それらの credentials を使って **新しい logon session** を **作成** できます:
```
runas /user:domain\username cmd.exe
```
**access token** は **LSASS** 内のログオンセッションへの **reference** も持っており、これはプロセスがネットワーク上のいくつかのオブジェクトにアクセスする必要がある場合に役立ちます。\
**ネットワークサービスにアクセスするために異なる credentials を使用する** プロセスは、次のように起動できます:
```
runas /user:domain\username /netonly cmd.exe
```
これは、ネットワーク内のオブジェクトにアクセスするための有用な credentials を持っているが、その credentials は current host 内では有効ではなく、ネットワーク内でのみ使われる場合に便利です（current host では現在のユーザー権限が使われます）。

#### `runas /netonly` details

`runas /netonly`（および `make_token` のような C2 helpers）は **`LOGON32_LOGON_NEW_CREDENTIALS`** token を作成します。これは lateral movement を理解するうえで非常に重要です。なぜなら:

- **Local** では、新しい process は **同じ local identity**、groups、integrity level、そして current token のほとんどの access decision を保持します。
- **Remote** では、outbound authentication に **指定した credentials** を SMB / WinRM / LDAP / HTTP / Kerberos / NTLM に対して使えます。
- したがって `whoami` はまだ **元の local user** を表示する一方で、network access は **別の account** として行われることがあります。

これは、credentials が domain や別の host では有効だが、user が current machine に **local logon できない、またはすべきでない** 場合に最適な選択肢です。

### Types of tokens

利用可能な token には2種類あります:

- **Primary Token**: process の security credentials を表現します。primary token の生成と process への関連付けは elevated privileges を必要とし、privilege separation の原則を強調します。通常、authentication service が token 生成を担当し、logon service がそれを user の operating system shell に関連付けます。process は生成時に親 process の primary token を継承する点に注意が必要です。
- **Impersonation Token**: server application が client の identity を一時的に採用し、secure objects にアクセスできるようにします。この仕組みは4つの operation level に分かれています:
- **Anonymous**: 未特定 user と同様の server access を与えます。
- **Identification**: server が client の identity を確認できるが、object access には使いません。
- **Impersonation**: server が client の identity の下で動作できます。
- **Delegation**: Impersonation に似ていますが、server が接続先の remote systems に対してこの identity の引き継ぎを拡張でき、credentials の保持を保証します。

#### Impersonate Tokens

metasploit の _**incognito**_ module を使うと、十分な privileges があれば他の **tokens** を簡単に **list** して **impersonate** できます。これは **他の user であるかのように actions を実行する** のに役立ちます。この technique で **privileges を escalate** することもできます。

運用中に忘れやすい実用的な注意点:

- **`CreateProcessWithTokenW`** は呼び出し元に **`SeImpersonatePrivilege`** を要求し、新しい process は **呼び出し元の session** で動作します。
- **`CreateProcessAsUserW`** は、`CreateProcessWithTokenW` が `1314` で失敗した場合、または token が参照する **session** で起動する必要がある場合の通常の fallback です。
- token が **`LogonUser(LOGON32_LOGON_NETWORK)`** 由来の場合、通常は **impersonation token** なので、process を起動する前に **`DuplicateTokenEx(..., TokenPrimary, ...)`** が必要です。
- すべての impersonation token が同じように有用なわけではありません: **`SecurityIdentification`** では user を確認できますが、**その user として行動することはできません**。coercion primitive や pipe/RPC client が identification-level token しか返さない場合は、**`TokenImpersonationLevel`** を確認し、**`SecurityImpersonation`** 以上を返す primitive に切り替えてください。

#### Token theft without touching LSASS

すでに **service** または **SYSTEM** の context があり、かつ **privileged user がログオンしている** なら、その user の token を盗むか複製する方が、**LSASS** を dump するより静かなことがよくあります。実際の侵入では、これだけで次のことが可能な場合が多いです:

- その user として local actions を実行する
- その user として remote resources にアクセスする
- reusable credentials を最初に抽出せずに AD operations を実行する

特権コンテキストからの **session/user token hijacking** の例は、[**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) を確認してください。**`WTSQueryUserToken`** のような API は **非常に信頼された services** を想定しており、通常は **`LocalSystem` + `SeTcbPrivilege`** が必要です。そのため、主にすでに service-level context を制御している場合に有用です。まず **SYSTEM** を得る特権別の方法については、以下のページを確認してください。

### Token Privileges

**privileges を escalate するために悪用できる token privileges** を学びましょう:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin) も確認してください。

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
