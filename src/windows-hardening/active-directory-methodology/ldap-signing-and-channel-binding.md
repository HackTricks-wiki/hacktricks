# LDAP Signing & Channel Binding 강화

{{#include ../../banners/hacktricks-training.md}}

## 왜 중요한가

LDAP relay/MITM는 공격자가 binds를 Domain Controllers로 전달해 인증된 컨텍스트를 얻을 수 있게 한다. 이러한 경로를 차단하는 서버측 제어는 두 가지이다:

- **LDAP Channel Binding (CBT)** 는 LDAPS bind를 특정 TLS 터널에 묶어 서로 다른 채널 간의 relays/replays를 차단한다.
- **LDAP Signing** 은 무결성이 보호된 LDAP 메시지를 강제하여 변조와 대부분의 서명되지 않은 relays를 방지한다.

**Server 2025 DCs**는 새로운 GPO(**LDAP server signing requirements Enforcement**)를 도입했으며, 해당 정책을 **Not Configured**로 두면 기본값이 **Require Signing** 이다. 강제를 피하려면 해당 정책을 명시적으로 **Disabled** 로 설정해야 한다.

## LDAP Channel Binding (LDAPS only)

- **요구 사항**:
- CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가한다.
- **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” 텔레메트리를 추가한다.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (기본값, CBT 없음)
- `When Supported` (감사: 실패 이벤트를 기록하지만 차단하지 않음)
- `Always` (강제: 유효한 CBT가 없는 LDAPS bind를 거부)
- **감사**: **When Supported** 로 설정해 다음을 확인:
- **3074** – 강제했을 경우 LDAPS bind가 CBT 검증에 실패했을 것.
- **3075** – LDAPS bind가 CBT 데이터를 생략했으며, 강제 시 거부되었을 것.
- (Event **3039**는 구버전 빌드에서 여전히 CBT 실패를 알린다.)
- **강제 적용**: LDAPS 클라이언트가 CBT를 전송하면 **Always** 로 설정; **LDAPS**에서만 효과가 있으며 (원시 389 포트에서는 적용되지 않음).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (최신 Windows의 기본값은 `Negotiate signing`).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).
- **Server 2025**: legacy 정책을 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled` 로 설정하라 (`Not Configured` = 기본적으로 강제됨; 강제를 피하려면 `Disabled` 로 설정).
- **호환성**: Windows **XP SP3+** 만 LDAP signing을 지원; 강제 적용 시 구형 시스템은 동작이 중단된다.

## 감사 중심 롤아웃 (권장 약 30일)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화하여 서명되지 않은 binds를 기록하도록 한다 (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements` = **When Supported**로 설정하여 CBT 텔레메트리를 시작합니다.
3. Directory Service 이벤트를 모니터링합니다:
- **2889** – unsigned/unsigned-allow 바인드 (서명 미준수).
- **3074/3075** – LDAPS 바인드가 실패하거나 CBT를 생략하는 경우(2019/2022에서는 KB4520412 및 위의 2단계 필요).
4. 별도 변경으로 적용:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 참고자료

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
