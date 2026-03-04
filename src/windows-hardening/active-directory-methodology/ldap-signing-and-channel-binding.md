# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## 왜 중요한가

LDAP relay/MITM은 공격자가 바인드를 도메인 컨트롤러로 전달해 인증된 컨텍스트를 얻을 수 있게 합니다. 서버 측 제어 두 가지가 이러한 경로를 차단합니다:

- **LDAP Channel Binding (CBT)**은 LDAPS 바인드를 특정 TLS 터널에 묶어 서로 다른 채널 간의 리레이/재생을 방지합니다.
- **LDAP Signing**은 무결성 보호된 LDAP 메시지를 강제하여 변조와 대부분의 서명되지 않은 리레이를 방지합니다.

**빠른 공격 확인**: `netexec ldap <dc> -u user -p pass` 같은 도구는 서버 포스처를 출력합니다. `(signing:None)` 및 `(channel binding:Never)`가 보이면 Kerberos/NTLM **relays to LDAP**가 가능하며(예: KrbRelayUp를 사용해 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 써서 RBCD를 구현하고 관리자로 가장함).

**Server 2025 DCs**는 새로운 GPO(**LDAP server signing requirements Enforcement**)를 도입했으며, 이 GPO는 **Not Configured** 상태일 때 기본적으로 **Require Signing**으로 설정됩니다. 강제를 피하려면 해당 정책을 명시적으로 **Disabled**로 설정해야 합니다.

## LDAP Channel Binding (LDAPS 전용)

- **Requirements**:
- CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가합니다.
- **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” 텔레메트리를 추가합니다.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (기본값, CBT 없음)
- `When Supported` (감사: 실패를 기록하지만 차단하지 않음)
- `Always` (강제: 유효한 CBT 없이 LDAPS 바인드를 거부함)
- **Audit**: 노출을 위해 **When Supported**로 설정:
- **3074** – 강제되었더라면 LDAPS 바인드가 CBT 검증에 실패했을 것입니다.
- **3075** – LDAPS 바인드가 CBT 데이터를 누락했으며 강제되었을 경우 거부되었을 것입니다.
- (이전 빌드에서는 이벤트 **3039**가 여전히 CBT 실패를 신호합니다.)
- **Enforcement**: LDAPS 클라이언트가 CBT를 전송하면 **Always**로 설정하십시오; **LDAPS**에만 적용되며 (raw 389에는 적용되지 않음).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (현대 Windows의 기본값인 `Negotiate signing` 대비).
- **DC GPO**:
- 레거시: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).
- **Server 2025**: 레거시 정책을 `None`으로 유지하고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정하십시오 (Not Configured = 기본적으로 강제됨; 강제를 피하려면 `Disabled`로 설정).
- **호환성**: LDAP signing을 지원하는 Windows는 **XP SP3+**뿐이며, 강제를 활성화하면 오래된 시스템은 동작이 중단됩니다.

## 우선 감사 기반 롤아웃 (권장: 약 30일)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화해 서명되지 않은 바인드를 기록합니다 (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements` = **When Supported**로 설정하여 CBT 텔레메트리를 시작합니다.
3. Directory Service 이벤트를 모니터링합니다:
- **2889** – unsigned/unsigned-allow binds (서명 비준수).
- **3074/3075** – CBT가 실패하거나 누락되는 LDAPS binds (2019/2022에서는 KB4520412 및 위 2단계 필요).
4. 별도의 변경으로 적용:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **또는** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 참고 자료

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
