# LDAP Signing & Channel Binding 강화

{{#include ../../banners/hacktricks-training.md}}

## 중요한 이유

LDAP relay/MITM 공격은 인증 정보를 도메인 컨트롤러로 전달해 인증된 LDAP 컨텍스트를 얻습니다. 서로 관련된 다음 두 가지 제어를 적용하면 이러한 공격 경로를 줄일 수 있습니다.

- **LDAP channel binding (CBT)**은 LDAPS에서 적용 가능한 인증을 TLS 서버 인증서/채널에 연결해 채널 간 relay를 어렵게 합니다.
- **LDAP signing**은 SASL LDAP bind에 무결성 보호를 요구합니다. 기밀성을 추가하지는 않으므로 LDAP 내용도 암호화해야 한다면 TLS를 사용하세요.<sup>[[2]](#references)</sup>

**빠른 보안 상태 확인**: `netexec ldap <dc> -u user -p pass` 같은 도구는 확인된 signing 및 channel-binding 정책을 보고합니다. `(signing:None)` 및 `(channel binding:Never)`는 제어가 적용되지 않았음을 나타내지만, relay 성공 여부는 캡처한 인증 유형, EPA 동작, 계정 권한, 대상 프로토콜 및 relay 보호 기능에 따라 달라집니다. relay된 주체에게 필요한 권한이 있으면 KrbRelayUp 같은 도구로 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 쓰고, resource-based constrained delegation (RBCD)을 구성한 다음, 그 위임 경로를 사용해 권한이 높은 주체를 가장할 수 있습니다.<sup>[[4]](#references)</sup>

**Server 2025 DC**에는 새 GPO(**LDAP server signing requirements Enforcement**)가 도입됩니다. 이 정책이 **Not Configured**로 남아 있으면 기본값은 **Require Signing**입니다. 강제 적용을 피하려면 정책을 명시적으로 **Disabled**로 설정해야 합니다.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS 전용)

- **요구 사항**:
  - CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가합니다.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” 원격 분석을 추가합니다.<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (기본값, CBT 사용 안 함)
  - `When Supported` (부분 적용: CBT를 지원하는 클라이언트는 유효한 토큰을 제공해야 합니다. CBT를 지원하지 않는 클라이언트는 계속 bind할 수 있으며, 감사 이벤트가 생성됩니다.)
  - `Always` (강제 적용: 유효한 CBT가 없는 LDAPS bind를 거부합니다.)<sup>[[1]](#references)</sup>
- **감사**: **When Supported**로 설정해 다음 이벤트를 확인합니다.
  - **3074** – 강제 적용 중이었다면 CBT 검증 실패로 LDAPS bind가 실패했을 상황입니다.
  - **3075** – LDAPS bind에 CBT 데이터가 누락되어 강제 적용 중이었다면 거부됐을 상황입니다.
  - (이전 빌드에서는 이벤트 **3039**도 CBT 실패를 나타냅니다.)<sup>[[1]](#references)[[2]](#references)</sup>
- **강제 적용**: LDAPS 클라이언트가 CBT를 전송하면 **Always**로 설정합니다. **LDAPS**에서만 효과가 있으며, 일반 389 포트에서는 적용되지 않습니다.<sup>[[1]](#references)</sup>

`When Supported`는 감사 전용 설정이 아닙니다. CBT를 지원하는 클라이언트의 CBT를 검증하면서 CBT를 지원하지 않는 클라이언트는 허용합니다. [Microsoft 정책 참조](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)에는 버전에 따른 기본값이 설명되어 있습니다. LDAP signing은 LDAP/389에서 적용 가능한 bind에 적용되며, channel binding은 TLS로 보호되는 LDAP 인증에 적용됩니다.


## LDAP Signing

- **클라이언트 GPO**: `Network security: LDAP client signing requirements` = `Require signing` (최신 Windows의 기본값인 `Negotiate signing`과 다름).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - 레거시: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: 레거시 정책은 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정합니다 (`Not Configured`는 기본적으로 강제 적용되며, 적용을 피하려면 `Disabled`로 설정).<sup>[[1]](#references)</sup>
- **호환성**: simple bind 또는 signing되지 않은 SASL bind를 사용하는 비 Windows 어플라이언스와 애플리케이션을 목록화합니다. Microsoft는 지원되는 Windows 버전에서의 지원을 문서화하고 있습니다. 레거시 클라이언트 호환성 관련 설명을 XP 버전 기준으로 단순화하지 말고 실제 클라이언트 스택에서 검증해야 합니다.<sup>[[2]](#references)</sup>

## 감사 우선 배포 (권장 기간 약 30일)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화해 signing되지 않은 bind를 기록합니다 (이벤트 **2889**).<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. 부분적인 CBT enforcement 및 telemetry를 위해 DC GPO `LDAP server channel binding token requirements` = **When Supported**로 설정합니다. 먼저 레거시 클라이언트와의 호환성을 확인하세요.<sup>[[1]](#references)</sup>
3. Directory Service 이벤트를 모니터링합니다:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 서명되지 않은/서명을 허용하는 바인드(서명 요구 사항 미준수).
   - **3074/3075** – 실패하거나 CBT를 누락할 LDAPS 바인드(2019/2022에서는 KB4520412 및 위의 2단계가 필요).
4. 별도의 변경으로 enforcement를 적용합니다:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (클라이언트).
   - `LDAP server signing requirements` = **Require signing** (DC) **또는** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP 채널 바인딩 및 LDAP 서명](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 채널 바인딩 및 서명 요구 사항](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 완화 업데이트](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP 서명 비활성화 → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
