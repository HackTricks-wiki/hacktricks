# 액세스 토큰

{{#include ../../banners/hacktricks-training.md}}

## 액세스 토큰

시스템에 **로그인한 각 사용자**는 해당 로그온 세션에 대한 **보안 정보가 포함된 액세스 토큰을 보유합니다**. 사용자가 로그온하면 시스템이 액세스 토큰을 생성합니다. **사용자를 대신해 실행되는 모든 프로세스**에는 **액세스 토큰의 복사본이 있습니다**. 토큰에는 사용자, 사용자의 그룹 및 사용자의 권한이 식별되어 있습니다. 또한 토큰에는 현재 로그온 세션을 식별하는 로그온 SID(Security Identifier)가 포함됩니다.

다음 명령을 실행하여 이 정보를 확인할 수 있습니다: `whoami /all`
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
또는 Sysinternals의 _Process Explorer_를 사용합니다(프로세스를 선택하고 "Security" 탭에 액세스).

![Access Tokens - Access Tokens: 또는 Sysinternals의 Process Explorer 사용(프로세스를 선택하고 "Security" 탭에 액세스)](<../../images/image (772).png>)

### 로컬 관리자

로컬 관리자가 로그인하면 **두 개의 access token이 생성됩니다**. 하나는 관리자 권한을 가지고, 다른 하나는 일반 권한을 가집니다. **기본적으로**, 이 사용자가 프로세스를 실행하면 **일반**(관리자가 아닌) **권한**을 가진 토큰이 사용됩니다. 이 사용자가 **관리자 권한으로** 무언가를 **실행**하려고 하면(예를 들어 "Run as Administrator"), **UAC**가 사용되어 권한을 요청합니다.\
[**UAC에 대해 자세히 알아보려면 이 페이지를 읽어보세요**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

실제로 이는 **권한 상승되지 않은 관리자 shell이 일반적으로 필터링된 토큰으로 실행된다**는 의미입니다. 따라서 프로세스가 권한 상승되기 전까지 `whoami /groups`에서 **`BUILTIN\Administrators`가 `Deny only`로 표시되는** 경우가 많습니다. 내부적으로 Windows는 **연결된 권한 상승 토큰**(`TokenLinkedToken`)을 유지하고 `TokenElevationType`과 같은 필드를 사용하여 상태를 추적합니다.

### 자격 증명을 사용한 사용자 impersonation

다른 사용자의 **유효한 자격 증명**을 가지고 있다면 해당 자격 증명으로 **새로운 logon session을 생성**할 수 있습니다:
```
runas /user:domain\username cmd.exe
```
**access token**에는 **LSASS** 내부의 로그온 세션에 대한 **reference**도 포함되어 있으며, 이는 프로세스가 네트워크의 일부 객체에 액세스해야 할 때 유용합니다.\
다음을 사용하면 **네트워크 서비스에 액세스할 때 다른 자격 증명을 사용하는 프로세스**를 실행할 수 있습니다:
```
runas /user:domain\username /netonly cmd.exe
```
네트워크의 객체에 접근할 수 있는 유효한 credentials는 있지만, 해당 credentials가 현재 host 내부에서는 유효하지 않을 때 유용합니다. 이러한 credentials는 네트워크에서만 사용되며, 현재 host에서는 현재 사용자의 권한이 사용됩니다.

#### `runas /netonly` details

`runas /netonly` (및 `make_token`과 같은 C2 helpers)는 **`LOGON32_LOGON_NEW_CREDENTIALS`** token을 생성합니다. 이는 lateral movement 중 이해해 두면 매우 유용합니다. <sup>[[3]](#references)</sup>

- **로컬에서는** 새 process가 현재 token과 **동일한 로컬 identity**, groups, integrity level 및 대부분의 동일한 access decisions를 유지합니다.
- **원격에서는** SMB / WinRM / LDAP / HTTP / Kerberos / NTLM에 대한 outbound authentication에 **제공된 credentials**를 사용할 수 있습니다.
- 따라서 `whoami`는 여전히 **원래 로컬 user**를 표시할 수 있지만, 네트워크 access는 **대체 account**로 수행됩니다.

이는 credentials가 domain 또는 다른 host에서 유효하지만, 해당 user가 현재 machine에 **로컬 log on할 수 없거나 log on해서는 안 되는** 경우에 매우 유용한 option입니다.

### Types of tokens

사용 가능한 token에는 두 가지 유형이 있습니다.

- **Primary Token**: Process의 security credentials를 나타냅니다. Primary token을 생성하고 process에 연결하는 작업에는 elevated privileges가 필요하며, 이는 privilege separation 원칙을 강조합니다. 일반적으로 authentication service가 token 생성을 담당하고, logon service가 이를 user의 operating system shell에 연결합니다. Process는 생성 시 parent process의 primary token을 상속한다는 점에 유의해야 합니다.
- **Impersonation Token**: Server application이 secure objects에 접근하기 위해 일시적으로 client의 identity를 채택할 수 있도록 합니다. 이 mechanism은 네 가지 operation level로 나뉩니다.
- **Anonymous**: 식별되지 않은 user와 유사한 server access를 부여합니다.
- **Identification**: Object access에 client identity를 사용하지 않고 server가 client의 identity를 확인할 수 있도록 합니다.
- **Impersonation**: Server가 client의 identity로 동작할 수 있도록 합니다.
- **Delegation**: Impersonation과 유사하지만, server가 상호작용하는 remote systems까지 이 identity assumption을 확장하여 credentials를 보존할 수 있습니다.

#### Impersonate Tokens

충분한 privileges가 있다면 metasploit의 _**incognito**_ module을 사용하여 다른 **tokens**를 쉽게 **list**하고 **impersonate**할 수 있습니다. 이는 **다른 user인 것처럼 actions를 수행**하는 데 유용합니다. 이 technique으로 **privileges를 escalate**할 수도 있습니다.

운영 중 쉽게 잊을 수 있는 몇 가지 실용적인 참고 사항입니다. <sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**는 caller에게 **`SeImpersonatePrivilege`**를 요구하며, 새 process는 **caller의 session**에서 실행됩니다.
- **`CreateProcessAsUserW`**는 `CreateProcessWithTokenW`가 `1314`와 함께 실패하거나, **token이 참조하는 session**에서 launch해야 할 때 사용하는 일반적인 fallback입니다.
- Token이 **`LogonUser(LOGON32_LOGON_NETWORK)`**에서 생성된 경우 일반적으로 **impersonation token**이므로, 이를 사용해 process를 spawn하기 전에 **`DuplicateTokenEx(..., TokenPrimary, ...)`**가 필요합니다.
- 모든 impersonation token이 동일하게 유용한 것은 아닙니다. **`SecurityIdentification`**은 user를 inspect할 수 있지만 **그 user로 동작할 수는 없습니다**. Coercion primitive 또는 pipe/RPC client가 identification-level token만 제공하는 경우 **`TokenImpersonationLevel`**을 확인하고 **`SecurityImpersonation`** 또는 그보다 높은 level을 제공하는 primitive로 전환해야 합니다.

#### Token theft without touching LSASS

이미 **service** 또는 **SYSTEM** context를 보유하고 있고 **privileged user가 log on한 상태**라면, 해당 user의 token을 steal하거나 duplicate하는 것이 **LSASS**를 dump하는 것보다 흔적이 적은 경우가 많습니다. 실제 침투에서는 다음 작업을 수행하기에 충분한 경우가 많습니다. <sup>[[2]](#references)</sup>

- 해당 user로 로컬 actions 실행
- 해당 user로 remote resources access
- 재사용 가능한 credentials를 먼저 extract하지 않고 AD operations 수행

Privileged context에서의 **session/user token hijacking** 예시는 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)를 참조하십시오. **`WTSQueryUserToken`**과 같은 APIs는 **highly trusted services**를 위한 것이며 일반적으로 **`LocalSystem` + `SeTcbPrivilege`**가 필요합니다. 따라서 이러한 APIs는 이미 service-level context를 control하고 있을 때 주로 유용합니다. 먼저 **SYSTEM**을 획득하는 privilege-specific 방법은 아래 pages를 참조하십시오.

### Token Privileges

다음 내용을 통해 **privileges를 escalate하는 데 악용할 수 있는 token privileges**를 알아보십시오.


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**가능한 모든 token privileges와 일부 definitions가 정리된 external page**](https://github.com/gtworek/Priv2Admin)를 확인하십시오.

## References

- [1] [Access Tokens 이해 및 악용 — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS를 건드리지 않고 Windows tokens를 악용하여 Active Directory compromise하기](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike의 "make_token" Command 이해하기](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
