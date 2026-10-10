# 액세스 토큰

{{#include ../../banners/hacktricks-training.md}}

## 액세스 토큰

모든 프로세스에는 보안 컨텍스트를 정의하는 **기본 액세스 토큰**이 있습니다. 스레드는 일반적으로 이 토큰을 사용하지만, 일시적으로 **가장 토큰**을 가질 수도 있습니다. 토큰에는 사용자 SID, 그룹 SID, 권한, 무결성 정보, 로그온 세션의 로그온 SID가 포함됩니다. 프로세스는 일반적으로 부모의 기본 토큰에 대한 참조를 상속하며, 토큰 내용을 독립적으로 복사해 받지는 않습니다.<sup>[[4]](#references)</sup>

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

또는 Sysinternals의 _Process Explorer_를 사용합니다(프로세스를 선택하고 "Security" 탭에 액세스).

![Access Tokens - Access Tokens: 또는 Sysinternals의 Process Explorer를 사용합니다(프로세스를 선택하고 "Security" 탭에 액세스)](<../../images/image (772).png>)

### 로컬 관리자

관리자에게 **UAC Admin Approval Mode**가 적용되면 대화형 로그온 시 전체 관리자 토큰과 필터링된 토큰이 생성됩니다. 기본적으로 Explorer와 일반 자식 프로세스는 필터링된 토큰을 사용합니다. **Run as administrator**와 같은 권한 상승 요청은 UAC에 프로그램을 전체 토큰으로 시작하도록 요청합니다. 정확한 동작은 기본 제공 Administrator 계정 사용 여부와 Admin Approval Mode의 사용 여부에 따라 달라집니다.<sup>[[5]](#references)</sup>

우회 기법과 정책 세부 정보는 전용 [**UAC 페이지**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)를 참조하세요.

실제로 이는 **권한 상승되지 않은 관리자 셸은 대개 필터링된 토큰으로 실행됨**을 의미합니다. 따라서 프로세스의 권한이 상승될 때까지 `whoami /groups`에 **`BUILTIN\Administrators`가 `Deny only`로 표시되는 경우가 많습니다**. 내부적으로 Windows는 **연결된 권한 상승 토큰**(`TokenLinkedToken`)을 유지하고 `TokenElevationType` 같은 필드로 상태를 추적합니다.

### 자격 증명을 이용한 사용자 가장

**다른 사용자의 유효한 자격 증명**이 있으면 해당 자격 증명으로 **새 로그온 세션을 생성**할 수 있습니다:

```
runas /user:domain\username cmd.exe
```

**access token**에는 **LSASS** 내부의 로그온 세션에 대한 **참조**도 포함되어 있습니다. 이는 프로세스가 네트워크의 일부 객체에 액세스해야 할 때 유용합니다.\
다음 명령을 사용하면 **네트워크 서비스에 액세스할 때 다른 자격 증명을 사용하는** 프로세스를 실행할 수 있습니다:

```
runas /user:domain\username /netonly cmd.exe
```

네트워크의 객체에 접근할 수 있는 유효한 자격 증명이 있지만, 해당 자격 증명이 네트워크에서만 사용되므로 현재 호스트에서는 유효하지 않을 때 유용합니다(현재 호스트에서는 현재 사용자의 권한이 사용됩니다).

#### `runas /netonly` 세부 정보

`runas /netonly`(및 `make_token`과 같은 C2 헬퍼)는 **`LOGON32_LOGON_NEW_CREDENTIALS`** 토큰을 생성합니다. 이는 lateral movement 중에 이해해 두면 매우 유용합니다.<sup>[[3]](#references)</sup>

- **로컬에서는** 새 프로세스가 현재 토큰과 **동일한 로컬 ID**, 그룹, 무결성 수준 및 대부분의 액세스 결정 사항을 유지합니다.
- **원격에서는** 아웃바운드 인증에 **제공된 자격 증명**을 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM에 사용할 수 있습니다.
- 따라서 네트워크 액세스는 **대체 계정**으로 이루어지더라도 `whoami`에는 여전히 **원래 로컬 사용자**가 표시될 수 있습니다.

자격 증명이 도메인이나 다른 호스트에서는 유효하지만, 사용자가 현재 컴퓨터에 **로컬로 로그온할 수 없거나 로그온해서는 안 될 때** 유용한 방법입니다.

### 토큰 유형

사용할 수 있는 토큰 유형은 두 가지입니다.<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: 프로세스 보안 컨텍스트를 나타냅니다. 일반적으로 자식 프로세스는 부모의 primary token을 상속하지만, 명시적 토큰을 사용하는 프로세스 생성 API에는 각각 자체적인 토큰 액세스 및 호출자 권한 요구 사항이 있습니다.
- **Impersonation token**: 서버 스레드가 액세스 검사 중에 클라이언트의 보안 컨텍스트를 일시적으로 사용하도록 합니다. 수준은 다음 네 가지입니다.
  - **Anonymous**: 식별되지 않은 사용자의 액세스와 유사한 수준의 서버 액세스를 허용합니다.
  - **Identification**: 서버가 클라이언트의 ID를 확인할 수 있지만, 객체 액세스에는 해당 ID를 사용할 수 없습니다.
  - **Impersonation**: 서버가 클라이언트의 ID로 작동할 수 있습니다.
  - **Delegation**: 인증 메커니즘과 계정 구성이 위임을 지원하는 경우, 서버가 원격 시스템에서 클라이언트를 가장할 수 있습니다.

#### 캡처한 토큰을 사용하기 전에 분류하기

사용자 이름만으로 토큰을 선택하지 마세요. 같은 계정에도 로그온 세션, 서비스 SID, 권한, 무결성 수준, 제한 사항 및 네트워크 자격 증명이 서로 다른 여러 토큰이 있을 수 있습니다.<sup>[[9]](#references)</sup> `GetTokenInformation`으로 최소한 **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, 그리고 **`TokenStatistics.AuthenticationId`**를 조회하세요.<sup>[[7]](#references)</sup>

제한된 토큰에는 deny-only SID, 제거된 권한 및 제한 SID가 포함될 수 있습니다. 제한 SID가 있으면 Windows는 활성화된 SID로 한 번, 제한 SID로 한 번 액세스 검사를 수행하며, **두 검사 모두 액세스를 허용해야 합니다**. 따라서 출력에 매력적으로 보이는 사용자 SID나 활성화된 그룹이 있다고 해서 해당 토큰으로 대상 객체에 접근할 수 있다는 뜻은 아닙니다.<sup>[[8]](#references)</sup>

문서화된 토큰 및 프로세스 생성 요구 사항에 따라 다음 순서로 판단하세요.<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token**을 `CreateProcessWithTokenW` 또는 `CreateProcessAsUserW`에 전달하려면 먼저 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` 권한이 있는 핸들이 필요합니다.
2. **Impersonation token**은 `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`로 변환합니다. Identification 수준 토큰은 ID 데이터를 노출할 수 있지만, 해당 클라이언트로 액세스 검사를 수행할 수는 없습니다.
3. `CreateProcessWithTokenW`에는 `SeImpersonatePrivilege`가 필요하며 자식 프로세스는 호출자의 세션에서 시작됩니다. 반면 `CreateProcessAsUserW`는 토큰의 세션을 사용하지만 일반적으로 `SeIncreaseQuotaPrivilege`가 필요하고 `SeAssignPrimaryTokenPrivilege`도 필요할 수 있습니다. 자격 증명을 사용할 수 있지만 이러한 권한이 없다면, 문서화된 대안은 `CreateProcessWithLogonW`입니다.

#### 프로세스 소유자뿐 아니라 토큰 핸들도 탐색하기

각 프로세스의 primary token을 여는 방식은 서비스 및 브로커 프로세스 내부에 일반 핸들로 보관된 **impersonation token**을 놓칠 수 있습니다. 재사용 가능한 핸들 테이블 워크플로는 시스템 핸들을 열거하고, 토큰 객체를 필터링한 다음, 각 소유 프로세스를 `PROCESS_DUP_HANDLE`로 열고, 후보 핸들을 현재 프로세스에 복제한 뒤 위 필드를 조회하는 것입니다. 복제된 핸들에 `TOKEN_QUERY` 및 `TOKEN_DUPLICATE`가 포함되어 있는지 확인하세요. 토큰 핸들이 보인다고 해서 이를 사용 가능한 primary token으로 복제할 수 있다는 의미는 아닙니다. 보호된 프로세스와 프로세스 DACL로 인해 소유 프로세스의 핸들을 열지 못할 수도 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`은 프로세스 primary token 및 보관된 토큰 핸들의 열거를 모두 자동화합니다. `list_token`은 사용자 이름마다 선호 후보 하나를 유지하고, `list_all_token`은 모든 후보를 출력합니다. PID를 지정하면 열거 대상이 소유 프로세스 하나로 제한됩니다.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

수동 검사 및 접근 확인을 위해 **TokenUniverse**는 프로세스/스레드 토큰을 열고, 기존 토큰 핸들을 검색하고, 제한 사항과 로그온 세션을 검사하고, 토큰을 복제하며, 여러 프로세스 생성 방식을 테스트할 수 있습니다.<sup>[[13]](#references)</sup> 기반이 되는 프로세스 간 핸들 primitive는 다음을 참조하세요.

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### 토큰 가장

충분한 권한이 있다면 Metasploit의 _**incognito**_ 모듈을 사용해 다른 **토큰**을 쉽게 **나열**하고 **가장**할 수 있습니다. 이를 통해 **다른 사용자로 동작하는 것처럼 작업을 수행**할 수 있습니다. 이 기법으로 **권한을 상승**할 수도 있습니다.

작업 중 쉽게 잊을 수 있는 몇 가지 실용적인 참고 사항입니다.<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**를 사용하려면 호출자에게 **`SeImpersonatePrivilege`**가 필요하며, 새 프로세스는 **호출자의 세션**에서 실행됩니다.
- **`CreateProcessWithTokenW`**가 `1314` 오류로 실패할 때 호출자가 필요한 권한을 충족하는 경우에만 **`CreateProcessAsUserW`**를 대안으로 사용할 수 있습니다. 자식 프로세스를 **토큰이 가리키는 세션**에서 실행해야 할 때도 올바른 선택입니다.<sup>[[9]](#references)[[10]](#references)</sup>
- 토큰이 **`LogonUser(LOGON32_LOGON_NETWORK)`**에서 온 경우 일반적으로 **가장 토큰**이므로, 이 토큰으로 프로세스를 생성하기 전에 **`DuplicateTokenEx(..., TokenPrimary, ...)`**를 호출해야 합니다.
- 가장 토큰이라고 해서 모두 똑같이 유용한 것은 아닙니다. **`SecurityIdentification`**은 사용자를 검사할 수 있게 하지만 **사용자처럼 동작할 수는 없습니다**. coercion primitive 또는 pipe/RPC 클라이언트에서 identification 수준의 토큰만 얻었다면 **`TokenImpersonationLevel`**을 확인하고 **`SecurityImpersonation`** 이상의 수준을 제공하는 primitive로 전환하세요.

#### LSASS에 접근하지 않고 토큰 탈취하기

이미 **service** 또는 **SYSTEM** 컨텍스트를 확보했고 **권한이 높은 사용자가 로그인되어 있다면**, 해당 사용자의 토큰을 탈취하거나 복제하는 편이 **LSASS** 덤프보다 흔적이 적은 경우가 많습니다. 실제 침해 사례에서는 다음 작업을 수행하기에 충분한 경우가 많습니다.<sup>[[2]](#references)</sup>

- 해당 사용자로 로컬 작업 실행
- 해당 사용자로 원격 리소스 접근
- 재사용 가능한 자격 증명을 먼저 추출하지 않고 AD 작업 수행

권한이 있는 컨텍스트에서 수행하는 **세션/사용자 토큰 하이재킹** 예시는 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)를 참조하세요. **`WTSQueryUserToken`**과 같은 API는 **높은 신뢰 수준의 서비스**를 위한 것으로, 일반적으로 **`LocalSystem` + `SeTcbPrivilege`**가 필요합니다. 따라서 이미 서비스 수준 컨텍스트를 제어하고 있을 때 주로 유용합니다. 먼저 **SYSTEM**을 획득하는 권한별 방법은 아래 페이지를 참조하세요.

### 토큰 권한

**권한 상승에 악용할 수 있는 토큰 권한**을 알아보세요.


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**가능한 모든 토큰 권한과 일부 정의가 있는 외부 페이지**](https://github.com/gtworek/Priv2Admin)를 확인하세요.

## References

- [1] [액세스 토큰 이해 및 악용 — 2부](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS에 접근하지 않고 Windows 토큰을 악용해 Active Directory 침해하기](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike의 "make_token" 명령 이해하기](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [액세스 토큰 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [사용자 계정 컨트롤 작동 방식 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [가장 수준 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS 열거형 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [제한된 토큰 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
