# アクセストークン

{{#include ../../banners/hacktricks-training.md}}

## アクセストークン

システムに**ログオンしている各ユーザーは、そのログオンセッションのセキュリティ情報を含むアクセストークンを保持します**。ユーザーがログオンすると、システムはアクセストークンを作成します。ユーザーに代わって**実行されるすべてのプロセス**は、**アクセストークンのコピーを保持します**。トークンは、ユーザー、ユーザーのグループ、およびユーザーの権限を識別します。トークンには、現在のログオンセッションを識別するログオン SID（Security Identifier）も含まれます。

`whoami /all`を実行すると、この情報を確認できます。
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
または、Sysinternals の _Process Explorer_ を使用します（プロセスを選択し、「Security」タブにアクセスします）：

![Access Tokens - Access Tokens: または、Sysinternals の Process Explorer を使用します（プロセスを選択し、「Security」タブにアクセスします）](<../../images/image (772).png>)

### ローカル administrator

ローカル administrator がログインすると、**2つの access token が作成されます**：1つは administrator 権限付きで、もう1つは通常権限付きです。**デフォルトでは**、このユーザーがプロセスを実行すると、**通常の**（administrator ではない）**権限**を持つ token が使用されます。このユーザーが何かを **administrator として実行**しようとすると（たとえば「Run as Administrator」）、**UAC** が使用され、許可を求められます。\
[**UAC の詳細については、このページを参照してください**](../authentication-credentials-uac-and-efs/index.html#uac)**。**

実際には、これは **elevate されていない admin shell は通常、filtered token で実行される**ことを意味します。そのため、プロセスが elevate されるまで、`whoami /groups` では **`BUILTIN\Administrators` が `Deny only` と表示される**ことがよくあります。内部的には、Windows は **linked elevated token**（`TokenLinkedToken`）を保持し、`TokenElevationType` などのフィールドで状態を追跡します。

### Credentials user impersonation

**他の任意のユーザーの有効な credentials を持っている場合**、その credentials を使用して **新しい logon session を作成**できます：
```
runas /user:domain\username cmd.exe
```
**access token**には、**LSASS**内のログオンセッションへの**reference**も含まれています。これは、processがネットワーク上の一部のobjectにアクセスする必要がある場合に便利です。\
次の方法で、**network servicesへのアクセスに異なるcredentialsを使用する**processを起動できます：
```
runas /user:domain\username /netonly cmd.exe
```
これは、ネットワーク上のオブジェクトにアクセスするための有効な credentials を持っているものの、それらの credentials が現在のホスト内では有効ではなく、ネットワーク内でのみ使用される場合に便利です（現在のホストでは、現在のユーザー権限が使用されます）。

#### `runas /netonly` の詳細

`runas /netonly`（および `make_token` などの C2 helpers）は、**`LOGON32_LOGON_NEW_CREDENTIALS`** token を作成します。これは lateral movement の際に理解しておくと非常に役立ちます。<sup>[[3]](#references)</sup>

- **ローカルでは**、新しいプロセスは現在の token と**同じローカル identity**、groups、integrity level、およびほとんど同じ access decisions を保持します。
- **リモートでは**、SMB / WinRM / LDAP / HTTP / Kerberos / NTLM への outbound authentication に、**指定した credentials**を使用できます。
- したがって、`whoami` は**元のローカル user**を表示したままでも、ネットワークアクセスは**別の account**として実行される場合があります。

これは、credentials が domain または別の host では有効であるものの、現在のマシンに対してその user が**ローカルログオンできない、またはログオンすべきではない**場合に最適な方法です。

### Token の種類

利用可能な token には2種類あります。

- **Primary Token**: process の security credentials を表します。primary token の作成および process への関連付けには elevated privileges が必要であり、これは privilege separation の原則を強調しています。通常、authentication service が token の作成を担当し、logon service が user の operating system shell への関連付けを処理します。process は作成時に親 process の primary token を継承する点にも注意してください。
- **Impersonation Token**: server application が secure objects にアクセスするため、一時的に client の identity を採用できるようにします。この仕組みには、次の4つの operation level があります。
- **Anonymous**: 識別されていない user と同等の server access を許可します。
- **Identification**: object access に client の identity を使用せず、server が client の identity を確認できるようにします。
- **Impersonation**: server が client の identity の下で動作できるようにします。
- **Delegation**: Impersonation に似ていますが、server が通信する remote systems に対してもこの identity の使用を拡張でき、credentials を保持できます。

#### Impersonate Tokens

metasploit の _**incognito**_ module を使用すると、十分な privileges がある場合、他の **tokens** を簡単に **list** および **impersonate** できます。これは、**別の user であるかのように actions を実行する**場合に便利です。この technique で**privileges を escalate**することもできます。

操作中に忘れやすい実用的な注意点をいくつか示します。<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** には caller の **`SeImpersonatePrivilege`** が必要で、新しい process は**caller の session**で実行されます。
- **`CreateProcessAsUserW`** は、`CreateProcessWithTokenW` が `1314` で失敗した場合、または token が参照する **session**で起動する必要がある場合に通常使用する fallback です。
- token が **`LogonUser(LOGON32_LOGON_NETWORK)`** から取得された場合、通常は**impersonation token**なので、process の spawn を試みる前に **`DuplicateTokenEx(..., TokenPrimary, ...)`** が必要です。
- すべての impersonation token が同じように有用なわけではありません。**`SecurityIdentification`** では user を inspect できますが、その user として **act**することはできません。coercion primitive または pipe/RPC client から identification-level token しか得られない場合は、**`TokenImpersonationLevel`**を確認し、**`SecurityImpersonation`**以上を返す primitive に切り替えてください。

#### LSASS に触れない Token theft

すでに **service** または **SYSTEM** context を取得しており、**privileged user がログオン中**である場合、その user の token を盗む、または duplicate する方が、**LSASS**を dump するより目立ちにくいことがよくあります。実際の多くの intrusion では、これだけで次のことが可能です。<sup>[[2]](#references)</sup>

- その user としてローカル actions を実行する
- その user として remote resources にアクセスする
- まず再利用可能な credentials を抽出せずに AD operations を実行する

privileged context からの **session/user token hijacking** の例については、[**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) を確認してください。**`WTSQueryUserToken`** などの API は**高度に信頼された services**向けであり、通常は **`LocalSystem` + `SeTcbPrivilege`** が必要です。そのため、主にすでに service-level context を control している場合に役立ちます。まず **SYSTEM** を取得する privilege-specific な方法については、以下の pages を確認してください。

### Token Privileges

**privileges を escalate するために abuse できる token privileges**について学びましょう。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**考えられるすべての token privileges とその定義を掲載した外部 page**](https://github.com/gtworek/Priv2Admin) も確認してください。

## References

- [1] [Access Tokens の理解と Abuse — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS に触れずに Windows の tokens を Abuse して Active Directory を compromise する](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike の "make_token" Command の謎を解明する](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
