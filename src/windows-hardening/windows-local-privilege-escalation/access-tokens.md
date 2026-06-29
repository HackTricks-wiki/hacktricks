# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

시스템에 **로그온한 각 사용자**는 해당 logon session에 대한 **security information이 포함된 access token**을 보유한다. 사용자가 로그온하면 시스템이 access token을 생성한다. 사용자 대신 **실행되는 모든 process**는 access token의 사본을 가진다. token은 user, user의 groups, 그리고 user의 privileges를 식별한다. token에는 현재 logon session을 식별하는 logon SID (Security Identifier)도 포함된다.

이 정보는 `whoami /all`를 실행하면 볼 수 있다
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

### Local administrator

로컬 administrator가 로그인하면 **두 개의 access token이 생성됩니다**: 하나는 admin 권한이 있고, 다른 하나는 일반 권한이 있습니다. **기본적으로**, 이 사용자가 process를 실행하면 **일반**(non-administrator) **권한의 token이 사용됩니다**. 이 사용자가 **administrator로 무언가를 실행**하려고 하면 ("Run as Administrator" 같은 경우) 권한을 요청하기 위해 **UAC**가 사용됩니다.\
[**UAC에 대해 더 알아보려면 이 페이지를 읽어보세요**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

실제로 이는 **non-elevated admin shell이 보통 filtered token으로 실행된다**는 뜻입니다. 그래서 `whoami /groups`는 process가 elevated 되기 전까지 종종 **`BUILTIN\Administrators`를 `Deny only`로 표시**합니다. 내부적으로 Windows는 **linked elevated token** (`TokenLinkedToken`)을 유지하고 `TokenElevationType` 같은 필드로 상태를 추적합니다.

### Credentials user impersonation

다른 사용자의 **유효한 credentials**이 있다면, 그 credentials로 **새로운 logon session을 생성**할 수 있습니다 :
```
runas /user:domain\username cmd.exe
```
**access token**에는 **LSASS** 내부의 logon session에 대한 **reference**도 있으며, 이는 process가 network의 일부 objects에 access해야 할 때 유용합니다.\
다음과 같이 **network services에 access하기 위해 다른 credentials를 사용하는** process를 실행할 수 있습니다:
```
runas /user:domain\username /netonly cmd.exe
```
네트워크의 객체에 접근하기 위한 유효한 credentials가 있지만, 그 credentials가 현재 호스트 내부에서는 유효하지 않고 네트워크에서만 사용되는 경우 유용합니다(현재 호스트에서는 현재 사용자 권한이 사용됩니다).

#### `runas /netonly` details

`runas /netonly` (그리고 `make_token` 같은 C2 helper)는 **`LOGON32_LOGON_NEW_CREDENTIALS`** token을 생성합니다. 이는 lateral movement를 이해할 때 매우 유용한데, 이유는 다음과 같습니다:

- **로컬에서는**, 새 process가 **같은 local identity**, groups, integrity level, 그리고 현재 token과 거의 동일한 access decision을 유지합니다.
- **원격에서는**, outbound authentication이 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM에 대해 **제공된 credentials**를 사용할 수 있습니다.
- 따라서 `whoami`는 여전히 **원래 local user**를 보여줄 수 있지만, network access는 **대체 계정**으로 수행됩니다.

이것은 credentials가 domain 또는 다른 host에서는 유효하지만, user가 현재 machine에 **local logon을 할 수 없거나 해서는 안 되는** 경우에 아주 좋은 옵션입니다.

### Types of tokens

사용 가능한 token에는 두 가지 유형이 있습니다:

- **Primary Token**: process의 security credentials를 나타냅니다. primary token을 process에 생성하고 연결하는 작업은 elevated privileges가 필요하며, privilege separation 원칙을 강조합니다. 일반적으로 authentication service가 token creation을 담당하고, logon service가 이를 사용자의 operating system shell과 연결합니다. process는 생성 시 부모 process의 primary token을 상속한다는 점도 중요합니다.
- **Impersonation Token**: server application이 secure object에 접근하기 위해 client의 identity를 일시적으로 채택할 수 있게 합니다. 이 메커니즘은 네 가지 operation level로 구분됩니다:
- **Anonymous**: 식별되지 않은 user와 유사하게 server access를 부여합니다.
- **Identification**: server가 client의 identity를 확인할 수는 있지만 object access에는 사용할 수 없습니다.
- **Impersonation**: server가 client의 identity 아래에서 동작할 수 있게 합니다.
- **Delegation**: Impersonation과 유사하지만, server가 상호작용하는 remote system으로 이 identity assumption을 확장할 수 있어 credential 보존을 보장합니다.

#### Impersonate Tokens

metasploit의 _**incognito**_ module을 사용하면 충분한 privileges가 있을 때 다른 **tokens**를 쉽게 **list**하고 **impersonate**할 수 있습니다. 이는 **다른 user인 것처럼 actions를 수행**할 때 유용할 수 있습니다. 이 technique으로 **privileges를 escalate**할 수도 있습니다.

운영 중 쉽게 잊기 쉬운 실용적인 메모:

- **`CreateProcessWithTokenW`**는 호출자에게 **`SeImpersonatePrivilege`**가 필요하며, 새 process는 **호출자의 session**에서 실행됩니다.
- **`CreateProcessAsUserW`**는 `CreateProcessWithTokenW`가 `1314`로 실패할 때, 또는 **token이 참조하는 session**에서 실행해야 할 때 사용하는 일반적인 대체 수단입니다.
- token이 **`LogonUser(LOGON32_LOGON_NETWORK)`**에서 왔다면, 보통 **impersonation token**이므로 process를 생성하기 전에 **`DuplicateTokenEx(..., TokenPrimary, ...)`**가 필요합니다.
- 모든 impersonation token이 똑같이 유용한 것은 아닙니다: **`SecurityIdentification`**은 user를 검사할 수는 있지만 **그 사람처럼 행동할 수는 없습니다**. coercion primitive나 pipe/RPC client가 identification-level token만 준다면 **`TokenImpersonationLevel`**을 확인하고, **`SecurityImpersonation`** 이상을 얻을 수 있는 primitive로 전환하세요.

#### LSASS를 건드리지 않고 Token theft

이미 **service** 또는 **SYSTEM** context가 있고 **privileged user가 logon된 상태**라면, 그 user의 token을 stealing하거나 duplicating하는 것이 **LSASS**를 dumping하는 것보다 더 조용한 경우가 많습니다. 실제 침투에서는 이것만으로도 다음이 가능합니다:

- 해당 user로 local actions 실행
- 해당 user로 remote resources 접근
- 재사용 가능한 credentials를 먼저 추출하지 않고도 AD operations 수행

특권 context에서의 **session/user token hijacking** 예시는 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)를 확인하세요. **`WTSQueryUserToken`** 같은 API는 **매우 신뢰받는 서비스**를 위해 만들어졌고 보통 **`LocalSystem` + `SeTcbPrivilege`**가 필요하므로, 주로 이미 service-level context를 장악한 뒤에 유용합니다. 먼저 **SYSTEM**을 얻는 특권별 방법은 아래 페이지를 확인하세요.

### Token Privileges

어떤 **token privileges를 악용해 privileges를 escalate**할 수 있는지 알아보세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**모든 가능한 token privileges와 몇 가지 정의가 있는 외부 페이지**](https://github.com/gtworek/Priv2Admin)도 참고하세요.

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
