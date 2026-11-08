# 액세스 토큰

{{#include ../../banners/hacktricks-training.md}}

## 액세스 토큰

모든 프로세스에는 보안 컨텍스트를 정의하는 **기본 액세스 토큰**이 있습니다. 스레드는 일반적으로 이 토큰을 사용하지만, 일시적으로 **가장 토큰**을 가질 수도 있습니다. 토큰에는 사용자 SID, 그룹 SID, 권한, 무결성 정보, 로그온 세션의 로그온 SID가 포함됩니다. 프로세스는 일반적으로 부모 프로세스의 기본 토큰에 대한 참조를 상속하며, 토큰 내용을 독립적으로 복사해 받지는 않습니다.<sup>[[4]](#references)</sup>

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

or using _Process Explorer_ from Sysinternals (프로세스를 선택하고 "Security" 탭에 접근):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### 로컬 관리자

**UAC Admin Approval Mode**가 관리자에게 적용되면, 대화형 로그온은 전체 관리자 토큰과 필터링된 토큰을 생성합니다. Explorer와 일반 자식 프로세스는 기본적으로 필터링된 토큰을 사용합니다. **Run as administrator**와 같은 권한 상승 요청은 UAC에 전체 토큰으로 프로그램을 시작하도록 요청합니다. 정확한 동작은 기본 제공 Administrator 계정 및 Admin Approval Mode가 비활성화된 경우에 따라 다릅니다.<sup>[[5]](#references)</sup>

우회 기법과 정책 세부 정보는 전용 [**UAC 페이지**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)를 참조하세요.

실제로 이는 **권한 상승되지 않은 관리자 셸은 대개 필터링된 토큰으로 실행된다**는 뜻입니다. 따라서 프로세스의 권한이 상승될 때까지 `whoami /groups`에 **`BUILTIN\Administrators`가 `Deny only`로 표시되는 경우가 많습니다**. 내부적으로 Windows는 **연결된 권한 상승 토큰**(`TokenLinkedToken`)을 유지하고, `TokenElevationType`과 같은 필드로 상태를 추적합니다.

### 자격 증명을 사용한 사용자 가장

다른 사용자의 **유효한 자격 증명**이 있으면 해당 자격 증명으로 **새 로그온 세션을 만들** 수 있습니다:

```
runas /user:domain\username cmd.exe
```

**access token**에는 **LSASS** 내부의 로그온 세션에 대한 **참조**도 포함되어 있습니다. 이는 프로세스가 네트워크의 일부 개체에 액세스해야 할 때 유용합니다.\
다음 명령을 사용하면 **네트워크 서비스에 액세스할 때 다른 자격 증명을 사용하는** 프로세스를 시작할 수 있습니다:

```
runas /user:domain\username /netonly cmd.exe
```

네트워크의 객체에 접근할 수 있는 유효한 자격 증명이 있지만, 현재 호스트에서는 해당 자격 증명이 유효하지 않고 네트워크에서만 사용되는 경우 유용합니다(현재 호스트에서는 현재 사용자의 권한이 사용됩니다).

#### `runas /netonly` 세부 정보

`runas /netonly`(및 `make_token` 같은 C2 helper)는 **`LOGON32_LOGON_NEW_CREDENTIALS`** 토큰을 생성합니다. 이는 lateral movement 중에 이해해 두면 매우 유용합니다.<sup>[[3]](#references)</sup>

- **로컬에서는** 새 프로세스가 현재 토큰과 **동일한 로컬 ID**, 그룹, 무결성 수준 및 대부분의 동일한 액세스 결정을 유지합니다.
- **원격에서는** 아웃바운드 인증에 **제공된 자격 증명**을 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM에 사용할 수 있습니다.
- 따라서 네트워크 액세스는 **대체 계정**으로 이루어지더라도 `whoami`에는 **원래 로컬 사용자**가 표시될 수 있습니다.

자격 증명은 도메인이나 다른 호스트에서 유효하지만, 사용자가 현재 시스템에 **로컬로 로그온할 수 없거나 그래서는 안 되는** 경우 좋은 선택입니다.

### 토큰 유형

사용할 수 있는 토큰 유형은 두 가지입니다.<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: 프로세스의 보안 컨텍스트를 나타냅니다. 일반적으로 자식 프로세스는 부모 프로세스의 primary token을 상속하지만, 명시적 토큰을 사용하는 프로세스 생성 API에는 별도의 토큰 액세스 및 호출자 권한 요구 사항이 적용됩니다.
- **Impersonation token**: 서버 스레드가 액세스 검사 중 클라이언트의 보안 컨텍스트를 일시적으로 사용하도록 합니다. 수준은 네 가지입니다.
  - **Anonymous**: 식별되지 않은 사용자와 유사한 서버 액세스 권한을 부여합니다.
  - **Identification**: 서버가 클라이언트의 ID를 확인할 수 있지만, 객체 액세스에 해당 ID를 사용할 수는 없습니다.
  - **Impersonation**: 서버가 클라이언트의 ID로 작업할 수 있도록 합니다.
  - **Delegation**: 인증 메커니즘과 계정 설정이 delegation을 지원하는 경우, 서버가 원격 시스템에서 클라이언트를 가장할 수 있도록 합니다.

#### 사용하기 전에 획득한 토큰을 분류하기

사용자 이름만으로 토큰을 선택하지 마세요. 동일한 계정에도 로그온 세션, 서비스 SID, 권한, 무결성 수준, 제한 사항 및 네트워크 자격 증명이 서로 다른 여러 토큰이 있을 수 있습니다.<sup>[[9]](#references)</sup> `GetTokenInformation`을 사용해 최소한 **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, **`TokenStatistics.AuthenticationId`**를 조회하세요.<sup>[[7]](#references)</sup>

제한된 토큰에는 deny-only SID, 제거된 권한 및 제한 SID가 포함될 수 있습니다. 제한 SID가 있으면 Windows는 활성화된 SID로 한 번, 제한 SID로 또 한 번 액세스 검사를 수행합니다. **두 검사 모두 액세스를 허용해야 합니다**. 따라서 출력에 매력적으로 보이는 사용자 SID나 활성화된 그룹이 있다고 해서 토큰이 대상 객체에 액세스할 수 있다고 단정할 수는 없습니다.<sup>[[8]](#references)</sup>

문서에 명시된 토큰 및 프로세스 생성 요구 사항에 따라 다음 절차를 따르세요.<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token**을 `CreateProcessWithTokenW` 또는 `CreateProcessAsUserW`에 전달하려면 먼저 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` 권한이 있는 핸들이 필요합니다.
2. **Impersonation token**은 `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`로 변환하세요. Identification 수준의 토큰으로 ID 데이터를 확인할 수는 있지만, 해당 클라이언트로 액세스 검사를 수행할 수는 없습니다.
3. `CreateProcessWithTokenW`에는 `SeImpersonatePrivilege`가 필요하며 자식 프로세스는 호출자의 세션에서 시작됩니다. 반면 `CreateProcessAsUserW`는 토큰의 세션을 사용하며, 일반적으로 `SeIncreaseQuotaPrivilege`가 필요하고 `SeAssignPrimaryTokenPrivilege`도 필요할 수 있습니다. 자격 증명을 사용할 수 있지만 이러한 권한이 없다면 문서에 명시된 대안은 `CreateProcessWithLogonW`입니다.

#### 프로세스 소유자뿐 아니라 토큰 핸들도 검색하기

각 프로세스의 primary token을 여는 것만으로는 서비스 및 broker 프로세스 내부에 일반 핸들로 유지되는 **impersonation token**을 놓칠 수 있습니다. 재사용 가능한 핸들 테이블 작업 흐름은 시스템 핸들을 열거하고, 토큰 객체를 필터링한 뒤, 각 소유자 프로세스를 `PROCESS_DUP_HANDLE` 권한으로 열고, 후보 핸들을 현재 프로세스에 복제한 다음 위 필드를 조회하는 것입니다. 복제된 핸들에 `TOKEN_QUERY`와 `TOKEN_DUPLICATE`가 포함되어 있는지 확인하세요. 토큰 핸들이 보인다고 해서 이를 사용 가능한 primary token으로 복제할 수 있다는 뜻은 아닙니다. 보호된 프로세스와 프로세스 DACL로 인해 소유자 프로세스의 핸들을 열지 못할 수도 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`은 프로세스 primary token과 유지된 토큰 핸들을 모두 자동으로 열거합니다. `list_token`은 사용자 이름마다 우선 후보 하나를 유지하고, `list_all_token`은 모든 후보를 출력합니다. PID를 지정하면 열거 대상이 소유자 프로세스 하나로 제한됩니다.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

수동 검사 및 접근 확인을 위해 **TokenUniverse**는 process/thread token을 열고, 기존 token handle을 검색하고, restriction과 logon session을 검사하고, token을 duplicate하며, 여러 process-creation method를 테스트할 수 있습니다.<sup>[[13]](#references)</sup> 기반이 되는 cross-process handle primitive는 다음을 참고하세요:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### 활성 thread impersonation token 찾기

service thread는 **process primary token**이 service account에 속하더라도 일시적으로 client를 impersonate할 수 있으므로, process-owner scan으로는 client context를 놓칠 수 있습니다.<sup>[[4]](#references)</sup> TokenUniverse는 접근 가능한 process/thread token을 나열할 수 있습니다. System Informer에서는 process의 **Threads** 탭을 열고 **Impersonation** 열을 확인해 후보 thread를 찾으세요.<sup>[[13]](#references)[[14]](#references)</sup>

특정 API를 확인하려면 `TH32CS_SNAPTHREAD` snapshot을 만들고, `THREADENTRY32.th32OwnerProcessID`를 service PID에 맞춰 필터링한 다음, 접근 가능한 각 thread에 대해 `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)`와 `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`을 호출하세요.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE`를 지정하면 token-open access check에서 caller의 **process** context를 사용합니다. scanner 자체가 identification level로 impersonate하는 경우 중요합니다.<sup>[[17]](#references)</sup> 위의 duplication/process-creation 절차를 시도하기 전에 token의 user, type, impersonation level 및 logon ID를 조회하세요.<sup>[[7]](#references)</sup> 열거와 open 사이에 thread가 impersonation을 중단할 수 있으며, token이 없는 경우, anonymous token, 보호된 thread, thread DACL 및 token DACL로 인해 수집하지 못할 수 있습니다.<sup>[[16]](#references)[[17]](#references)</sup> service가 보유한 token handle을 검색하는 것과 달리, 이 방법은 **현재 할당된 thread token**을 확인합니다.

기존 thread를 검색하는 대신 권한이 있는 client가 사용자의 pipe에 연결하도록 하여 thread token을 얻는 attack path는 [named-pipe client impersonation](named-pipe-client-impersonation.md)을 참고하세요.

#### Token impersonate하기

충분한 권한이 있다면 metasploit의 _**incognito**_ module을 사용해 다른 **token**을 쉽게 **나열**하고 **impersonate**할 수 있습니다. 이를 통해 **다른 사용자인 것처럼 작업**할 수 있으며, 이 기법으로 **privilege escalation**을 수행할 수도 있습니다.

운용 중에 잊기 쉬운 실용적인 참고 사항:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**를 호출하려면 caller에 **`SeImpersonatePrivilege`**가 필요하며, 새 process는 **caller의 session**에서 실행됩니다.
- **`CreateProcessWithTokenW`**가 `1314` 오류로 실패했을 때 caller가 필요한 privilege를 갖춘 경우에만 **`CreateProcessAsUserW`**를 대안으로 사용할 수 있습니다. child를 **token이 가리키는 session**에서 실행해야 할 때도 이 함수를 사용해야 합니다.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`**는 **impersonation token**을 반환합니다. process를 만들기 전에 **`DuplicateTokenEx(..., TokenPrimary, ...)`**로 변환하세요. 변환 후에도 해당 process는 이 network logon을 사용해 인증이 필요한 remote share나 printer에 접근할 수 없습니다. 이 logon type은 credential을 cache하지 않기 때문입니다. credential을 보유하고 있고 이후 network access가 필요하다면 interactive 또는 network-cleartext logon을 사용하세요. local identity는 유지하면서 outbound credential을 제공하는 `LOGON32_LOGON_NEW_CREDENTIALS`(`runas /netonly`)와 혼동하지 마세요.<sup>[[18]](#references)</sup>
- 모든 impersonation token의 유용성이 같은 것은 아닙니다. **`SecurityIdentification`**을 사용하면 user를 검사할 수 있지만 **그 user로 동작할 수는 없습니다**. coercion primitive나 pipe/RPC client에서 identification-level token만 제공되는 경우 **`TokenImpersonationLevel`**을 확인하고 **`SecurityImpersonation`** 이상을 제공하는 primitive로 전환하세요.

#### LSASS에 접근하지 않고 token 탈취하기

이미 **service** 또는 **SYSTEM** context를 확보했고 **권한이 높은 사용자가 로그인한 상태**라면, 해당 사용자의 token을 탈취하거나 duplicate하는 방법이 **LSASS** dump보다 흔히 더 은밀합니다. 실제 침해 사례에서는 다음 작업을 수행하는 데 충분한 경우가 많습니다:<sup>[[2]](#references)</sup>

- 해당 사용자로 local 작업 실행
- 해당 사용자로 remote resource에 접근
- 재사용 가능한 credential을 먼저 추출하지 않고 AD 작업 수행

권한 있는 context에서 **session/user token hijacking**을 수행하는 예시는 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)를 참고하세요. **`WTSQueryUserToken`**과 같은 API는 **높은 신뢰 수준의 service**를 위한 것이며 보통 **`LocalSystem` + `SeTcbPrivilege`**가 필요하므로, 주로 이미 service-level context를 제어하고 있을 때 유용합니다. 먼저 **SYSTEM**을 획득하는 privilege별 방법은 아래 페이지를 참고하세요.

### Token Privileges

**privilege escalation에 악용할 수 있는 token privilege**를 알아보세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**가능한 모든 token privilege와 일부 정의를 설명하는 외부 페이지**](https://github.com/gtworek/Priv2Admin)를 참고하세요.



## References

- [1] [Access Token 이해 및 악용 — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS에 접근하지 않고 Windows token을 악용해 Active Directory 침해하기](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike의 "make_token" 명령 이해하기](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Token - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [사용자 계정 컨트롤 작동 방식 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation Level - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS 열거형 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [제한된 Token - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle 함수 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [System Informer thread-token 기능 요청](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Thread 목록 순회 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
