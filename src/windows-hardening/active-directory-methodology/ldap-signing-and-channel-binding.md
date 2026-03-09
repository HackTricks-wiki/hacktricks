# LDAP 서명 및 채널 바인딩 강화

{{#include ../../banners/hacktricks-training.md}}

## 왜 중요한가

LDAP relay/MITM은 공격자가 바인드를 Domain Controllers로 전달하여 인증된 컨텍스트를 얻도록 허용한다. 서버 측 제어 두 가지가 이러한 경로를 차단한다:

- **LDAP Channel Binding (CBT)**는 특정 TLS 터널에 LDAPS 바인드를 묶어 서로 다른 채널 간의 relays/replays를 무력화한다.
- **LDAP Signing**은 무결성으로 보호된 LDAP 메시지를 강제하여 변조와 대부분의 서명되지 않은 relays를 방지한다.

**빠른 공격 측 확인**: `netexec ldap <dc> -u user -p pass` 같은 도구는 서버 상태를 출력한다. `(signing:None)` 및 `(channel binding:Never)`가 표시되면 Kerberos/NTLM **relays to LDAP**가 가능하다(예: KrbRelayUp를 사용하여 RBCD용 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 쓰고 관리자로 가장).

**Server 2025 DCs**는 새 GPO(**LDAP server signing requirements Enforcement**)를 도입하며, 이 GPO는 **Not Configured**로 둔 경우 기본적으로 **Require Signing**으로 적용된다. 강제 적용을 피하려면 해당 정책을 명시적으로 **Disabled**로 설정해야 한다.

## LDAP Channel Binding (LDAPS 전용)

- **Requirements**:
- CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가한다.
- **KB4520412**(Server 2019/2022)는 LDAPS CBT “what-if” 텔레메트리를 추가한다.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (기본값, CBT 없음)
- `When Supported` (감사: 실패를 기록하지만 차단하지 않음)
- `Always` (강제: 유효한 CBT 없는 LDAPS 바인드를 거부)
- **Audit**: 다음을 노출하려면 **When Supported**로 설정:
- **3074** – 강제했으면 LDAPS 바인드가 CBT 검증에 실패했을 것임.
- **3075** – LDAPS 바인드가 CBT 데이터를 누락했으며 강제했으면 거부되었을 것임.
- (이전 빌드에서는 이벤트 **3039**가 여전히 CBT 실패를 알린다.)
- **Enforcement**: LDAPS 클라이언트가 CBT를 전송하면 **Always**로 설정; **LDAPS**에서만 효과(원시 389는 해당 없음).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (현대 Windows의 기본값은 `Negotiate signing`).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).
- **Server 2025**: 레거시 정책을 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정( Not Configured = 기본적으로 강제 적용; 피하려면 `Disabled`로 설정).
- **Compatibility**: LDAP signing을 지원하는 것은 Windows **XP SP3+**만 해당; 강제 적용 시 구형 시스템은 작동이 중단된다.

## 우선 감사 기반 배포(권장 약 30일)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화하여 서명되지 않은 바인드를 로깅(Event **2889**)하도록 설정:
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT 텔레메트리를 시작하려면 DC GPO `LDAP server channel binding token requirements` = **When Supported**로 설정합니다.
3. Directory Service 이벤트를 모니터링합니다:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (2019/2022에서는 KB4520412와 위 2단계가 필요합니다).
4. 별도의 변경으로 강제 적용합니다:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 참고자료

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
