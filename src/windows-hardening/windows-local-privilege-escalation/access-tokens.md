# 액세스 토큰

{{#include ../../banners/hacktricks-training.md}}

## 액세스 토큰

모든 프로세스에는 보안 컨텍스트를 정의하는 **기본 액세스 토큰**이 있습니다. 스레드는 일반적으로 해당 토큰을 사용하지만, 일시적으로 **가장 토큰**을 사용할 수도 있습니다. 토큰에는 사용자 SID, 그룹 SID, 권한, 무결성 정보, 그리고 로그온 세션의 로그온 SID가 포함됩니다. 프로세스는 일반적으로 부모 프로세스의 기본 토큰에 대한 참조를 상속하며, 토큰 내용의 독립적인 복사본을 받지는 않습니다.<sup>[[4]](#references)</sup>

`whoami /all`을 실행하면 이 정보를 확인할 수 있습니다.

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

or Sysinternals의 _Process Explorer_를 사용합니다(프로세스를 선택하고 "Security" 탭에 액세스):

![액세스 토큰 - 액세스 토큰: 또는 Sysinternals의 Process Explorer를 사용합니다(프로세스를 선택하고 "Security" 탭에 액세스)](<../../images/image (772).png>)

### 로컬 관리자

**UAC Admin Approval Mode**가 관리자 계정에 적용되면 대화형 로그온 시 전체 관리자 토큰과 필터링된 토큰이 생성됩니다. Explorer와 일반 자식 프로세스는 기본적으로 필터링된 토큰을 사용합니다. **Run as administrator**와 같은 권한 상승 요청은 UAC에 전체 토큰으로 프로그램을 시작하도록 요청합니다. 정확한 동작은 기본 제공 Administrator 계정 사용 여부와 Admin Approval Mode의 활성화 여부에 따라 다릅니다.<sup>[[5]](#references)</sup>

우회 기법과 정책 세부 정보는 전용 [**UAC 페이지**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)를 참조하세요.

실제로 이는 **권한 상승되지 않은 관리자 셸은 대개 필터링된 토큰으로 실행됨**을 의미합니다. 따라서 프로세스의 권한이 상승되기 전까지 `whoami /groups`에 **`BUILTIN\Administrators`가 `Deny only`로 표시되는 경우가 많습니다**. 내부적으로 Windows는 **연결된 권한 상승 토큰**(`TokenLinkedToken`)을 유지하고 `TokenElevationType`과 같은 필드로 상태를 추적합니다.

### 자격 증명을 사용한 사용자 가장

다른 사용자의 **유효한 자격 증명**이 있으면 해당 자격 증명으로 **새 로그온 세션을 생성**할 수 있습니다:

```
runas /user:domain\username cmd.exe
```

**access token**에는 **LSASS** 내 로그온 세션에 대한 **reference**도 포함되어 있습니다. 이는 프로세스가 네트워크의 일부 개체에 액세스해야 할 때 유용합니다.\
다음과 같이 **네트워크 서비스에 액세스할 때 다른 자격 증명을 사용하는** 프로세스를 시작할 수 있습니다:

```
runas /user:domain\username /netonly cmd.exe
```

네트워크의 객체에 접근하는 데 유효한 자격 증명이 있지만, 해당 자격 증명은 네트워크에서만 사용되므로 현재 호스트에서는 유효하지 않을 때 유용합니다(현재 호스트에서는 현재 사용자의 권한이 사용됩니다).

#### `runas /netonly` 세부 정보

`runas /netonly`(및 `make_token`과 같은 C2 helper)는 **`LOGON32_LOGON_NEW_CREDENTIALS`** token을 생성합니다. lateral movement 중 이를 이해해 두면 매우 유용합니다.<sup>[[3]](#references)</sup>

- **로컬에서는** 새 프로세스가 현재 token과 **동일한 로컬 identity**, 그룹, integrity level, 그리고 대부분 동일한 access decision을 유지합니다.
- **원격에서는** 아웃바운드 인증에 **제공된 자격 증명**을 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM에 사용할 수 있습니다.
- 따라서 네트워크 접근이 **대체 계정**으로 이루어지는 동안에도 `whoami`에는 **원래 로컬 사용자**가 표시될 수 있습니다.

자격 증명이 도메인이나 다른 호스트에서는 유효하지만 사용자가 현재 컴퓨터에 **로컬로 로그온할 수 없거나 로그온해서는 안 될 때** 유용한 옵션입니다.

### token 유형

사용 가능한 token에는 두 가지 유형이 있습니다.<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: 프로세스의 security context를 나타냅니다. 일반적으로 자식 프로세스는 부모 프로세스의 primary token을 상속하지만, 명시적 token을 사용하는 프로세스 생성 API에는 각각 자체적인 token 접근 및 호출자 권한 요구 사항이 있습니다.
- **Impersonation token**: 서버 스레드가 접근 검사에 클라이언트의 security context를 일시적으로 사용하도록 합니다. 수준은 다음 네 가지입니다.
  - **Anonymous**: 미확인 사용자가 접근할 수 있는 수준으로 서버 접근을 허용합니다.
  - **Identification**: 객체 접근에 사용하지 않고도 서버가 클라이언트의 identity를 확인할 수 있게 합니다.
  - **Impersonation**: 서버가 클라이언트의 identity로 동작할 수 있게 합니다.
  - **Delegation**: 인증 메커니즘과 계정 설정이 delegation을 지원하는 경우 서버가 원격 시스템에서 클라이언트를 impersonate할 수 있게 합니다.

#### 사용하기 전에 캡처한 token 분류하기

사용자 이름만 보고 token을 선택하지 마세요. 동일한 계정에도 서로 다른 logon session, service SID, 권한, integrity level, 제한 사항, 네트워크 자격 증명을 가진 token이 여러 개 있을 수 있습니다.<sup>[[9]](#references)</sup> `GetTokenInformation`을 사용해 최소한 **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, **`TokenStatistics.AuthenticationId`**를 조회하세요.<sup>[[7]](#references)</sup>

제한된 token에는 deny-only SID, 제거된 권한, restricting SID가 포함될 수 있습니다. restricting SID가 있으면 Windows는 활성화된 SID로 한 번, restricting SID로 다시 한 번 접근 검사를 수행하며, **두 검사 모두 접근을 허용해야 합니다**. 따라서 출력에 매력적인 사용자 SID나 활성화된 그룹이 보인다고 해서 해당 token으로 대상 객체에 접근할 수 있다고 단정할 수는 없습니다.<sup>[[8]](#references)</sup>

문서화된 token 및 프로세스 생성 요구 사항에 따라 다음 절차를 따르세요.<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token**을 `CreateProcessWithTokenW` 또는 `CreateProcessAsUserW`에 전달하려면 먼저 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` 권한이 있는 handle이 필요합니다.
2. **Impersonation token**은 `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`를 사용해 변환합니다. Identification 수준 token은 identity 데이터를 노출할 수 있지만 해당 클라이언트로서 접근 검사를 수행할 수는 없습니다.
3. `CreateProcessWithTokenW`에는 `SeImpersonatePrivilege`가 필요하며 호출자의 session에서 자식 프로세스를 시작합니다. 반면 `CreateProcessAsUserW`는 token의 session을 사용하지만 일반적으로 `SeIncreaseQuotaPrivilege`가 필요하고, `SeAssignPrimaryTokenPrivilege`도 필요할 수 있습니다. 자격 증명은 있지만 이러한 권한이 없다면 문서화된 대안은 `CreateProcessWithLogonW`입니다.

#### 프로세스 소유자뿐 아니라 token handle도 탐색하기

각 프로세스의 primary token을 여는 것만으로는 서비스 및 broker 프로세스 내부에 일반 handle로 보관된 **impersonation token**을 놓칠 수 있습니다. 재사용 가능한 handle-table workflow는 시스템 handle을 열거하고, token 객체를 필터링한 뒤, 각 소유자 프로세스를 `PROCESS_DUP_HANDLE`로 열고, 후보 handle을 현재 프로세스에 복제한 다음 위의 필드를 조회하는 방식입니다. 복제된 handle에 `TOKEN_QUERY`와 `TOKEN_DUPLICATE`가 포함되어 있는지 확인하세요. token handle이 보인다고 해서 이를 사용 가능한 primary token으로 복제할 수 있는 것은 아닙니다. 보호된 프로세스와 프로세스 DACL 때문에 소유자 프로세스의 handle을 열지 못할 수도 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`은 프로세스 primary token과 보관된 token handle을 모두 자동으로 열거합니다. `list_token`은 사용자 이름별로 우선 후보 하나를 유지하고, `list_all_token`은 모든 후보를 출력합니다. PID를 지정하면 열거 대상이 소유자 프로세스 하나로 제한됩니다.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

수동으로 검사하고 접근을 확인할 때 **TokenUniverse**를 사용하면 프로세스/스레드 토큰을 열고, 기존 토큰 핸들을 검색하고, 제한 사항과 로그온 세션을 검사하고, 토큰을 복제하고, 여러 프로세스 생성 방법을 테스트할 수 있습니다.<sup>[[13]](#references)</sup> 기반이 되는 프로세스 간 핸들 primitive에 대해서는 다음을 참조하세요.

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### 토큰 가장

충분한 권한이 있다면 Metasploit의 _**incognito**_ 모듈을 사용해 다른 **토큰**을 쉽게 **나열**하고 **가장**할 수 있습니다. 이를 통해 **다른 사용자인 것처럼 작업을 수행**할 수 있습니다. 이 기법으로 **권한 상승**을 시도할 수도 있습니다.

작업 중 잊기 쉬운 실용적인 참고 사항:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**를 사용하려면 호출자에게 **`SeImpersonatePrivilege`**가 있어야 하며, 새 프로세스는 **호출자의 세션**에서 실행됩니다.
- **`CreateProcessWithTokenW`**가 `1314` 오류와 함께 실패한 경우, 호출자가 해당 권한 요구 사항을 충족할 때만 **`CreateProcessAsUserW`**를 대안으로 사용할 수 있습니다. 자식 프로세스를 **토큰이 가리키는 세션**에서 실행해야 할 때도 이 함수를 사용해야 합니다.<sup>[[9]](#references)[[10]](#references)</sup>
- 토큰이 **`LogonUser(LOGON32_LOGON_NETWORK)`**에서 나온 경우 대개 **가장 토큰**이므로, 프로세스 생성에 사용하기 전에 **`DuplicateTokenEx(..., TokenPrimary, ...)`**를 호출해야 합니다.
- 모든 가장 토큰이 똑같이 유용한 것은 아닙니다. **`SecurityIdentification`**은 사용자를 검사할 수 있지만 **사용자처럼 행동할 수는 없습니다**. coercion primitive나 pipe/RPC 클라이언트가 식별 수준 토큰만 제공한다면 **`TokenImpersonationLevel`**을 확인하고 **`SecurityImpersonation`** 이상을 제공하는 primitive를 사용하세요.

#### LSASS에 접근하지 않고 토큰 탈취하기

이미 **서비스** 또는 **SYSTEM** 컨텍스트를 확보했고 **권한이 높은 사용자가 로그인한 상태**라면, 해당 사용자의 토큰을 훔치거나 복제하는 편이 **LSASS** 덤프보다 흔적이 적은 경우가 많습니다. 실제 침해 사례에서는 다음 작업을 수행하기에 충분한 경우가 많습니다.<sup>[[2]](#references)</sup>

- 해당 사용자로 로컬 작업 수행
- 해당 사용자로 원격 리소스에 접근
- 재사용 가능한 자격 증명을 먼저 추출하지 않고 AD 작업 수행

권한 있는 컨텍스트에서 **세션/사용자 토큰을 하이재킹**하는 예제는 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)를 참조하세요. **`WTSQueryUserToken`**과 같은 API는 **높은 신뢰 수준의 서비스**를 대상으로 하며, 일반적으로 **`LocalSystem` + `SeTcbPrivilege`**가 필요합니다. 따라서 서비스 수준 컨텍스트를 이미 제어하고 있을 때 주로 유용합니다. 먼저 **SYSTEM**을 얻는 권한별 방법은 아래 페이지를 참조하세요.

### 토큰 권한

**권한 상승에 악용할 수 있는 토큰 권한**을 알아보세요.


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**가능한 모든 토큰 권한과 몇 가지 정의가 있는 외부 페이지**](https://github.com/gtworek/Priv2Admin)를 확인하세요.

## References

- [1] [액세스 토큰의 이해와 악용 — 2부](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS에 접근하지 않고 Windows 토큰을 악용해 Active Directory 침해하기](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike의 "make_token" 명령 알아보기](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [액세스 토큰 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [사용자 계정 컨트롤의 작동 방식 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [가장 수준 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS 열거형 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [제한된 토큰 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
