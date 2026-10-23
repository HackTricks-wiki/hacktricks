# LDAP Signing 및 Channel Binding 강화

{{#include ../../banners/hacktricks-training.md}}

## 중요한 이유

LDAP relay/MITM 공격은 인증을 도메인 컨트롤러로 전달해 인증된 LDAP 컨텍스트를 얻습니다. [name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)에서는 더 광범위한 공격 흐름을 다룹니다. 서로 관련된 두 가지 제어 기능으로 이러한 공격 경로를 줄일 수 있습니다.

- **LDAP channel binding (CBT)**은 LDAPS에서 사용하는 TLS 서버 인증서/채널에 해당 인증을 바인딩해 교차 채널 relay를 어렵게 합니다.
- **LDAP signing**은 SASL LDAP bind에 무결성 보호를 요구합니다. 기밀성을 추가하지는 않으므로 LDAP 내용도 암호화해야 한다면 TLS를 사용하세요.<sup>[[2]](#references)</sup>

**빠른 상태 확인**: `netexec ldap <dc> -u user -p pass`와 같은 도구는 관찰된 signing 및 channel-binding 정책을 보고합니다. `(signing:None)` 및 `(channel binding:Never)`는 제어 기능이 누락되었음을 나타내지만, relay 성공 여부는 캡처한 인증 유형, EPA 동작, 계정 권한, 대상 프로토콜 및 relay 방어 기능에 따라 달라집니다. relay된 주체에 필요한 권한이 있으면 KrbRelayUp과 같은 도구로 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 기록하고, resource-based constrained delegation (RBCD)을 구성한 다음, 해당 위임 경로를 이용해 권한이 높은 주체를 가장할 수 있습니다.<sup>[[4]](#references)</sup>

**Server 2025 DC**에는 새 GPO(**LDAP server signing requirements Enforcement**)가 도입되었습니다. 이 정책이 **Not Configured**인 경우 기본값은 **Require Signing**입니다. 적용을 피하려면 정책을 명시적으로 **Disabled**로 설정해야 합니다.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS 전용)

- **요구 사항**:
  - CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가합니다.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” 원격 분석을 추가합니다.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (기본값, CBT 사용 안 함)
  - `When Supported` (부분 적용: CBT를 지원하는 클라이언트는 유효한 토큰을 제공해야 합니다. CBT를 지원하지 않는 클라이언트는 계속 bind할 수 있으며, 감사 이벤트가 기록됩니다.)
  - `Always` (적용: 유효한 CBT가 없는 LDAPS bind를 거부합니다.)<sup>[[1]](#references)</sup>
- **감사**: 다음 이벤트를 확인하려면 **When Supported**로 설정합니다.
  - **3074** – 적용 모드였다면 CBT 검증 실패로 LDAPS bind가 실패했을 상황입니다.
  - **3075** – LDAPS bind에 CBT 데이터가 누락되어 적용 모드였다면 거부되었을 상황입니다.
  - (이전 빌드에서는 이벤트 **3039**도 CBT 실패를 나타냅니다.)<sup>[[1]](#references)[[2]](#references)</sup>
- **적용**: LDAPS 클라이언트가 CBT를 전송하면 **Always**로 설정합니다. 이 설정은 **LDAPS**에서만 적용되며, 일반 389 포트에는 적용되지 않습니다.<sup>[[1]](#references)</sup>

`When Supported`는 감사 전용 설정이 아닙니다. CBT를 지원하는 클라이언트의 CBT를 검증하면서 CBT를 지원하지 않는 클라이언트는 허용합니다. [Microsoft 정책 참조](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)에서 버전에 따라 달라지는 기본값을 설명합니다. LDAP signing은 LDAP/389에서 해당하는 bind에 적용되며, channel binding은 TLS로 보호되는 LDAP 인증에 적용됩니다.

## LDAP Signing

- **클라이언트 GPO**: `Network security: LDAP client signing requirements` = `Require signing` (최신 Windows의 기본값인 `Negotiate signing`과 다름).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - 레거시: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: 레거시 정책은 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정합니다 (`Not Configured`는 기본적으로 적용됨. 적용을 피하려면 `Disabled`로 설정).<sup>[[1]](#references)</sup>
- **호환성**: simple bind 또는 서명되지 않은 SASL bind를 사용하는 비 Windows 어플라이언스와 애플리케이션을 파악합니다. Microsoft는 지원 대상 Windows 버전에서의 지원을 문서화하고 있습니다. 레거시 클라이언트 호환성 관련 내용은 XP 버전 기준으로 단순화하지 말고 실제 클라이언트 스택을 확인해야 합니다.<sup>[[2]](#references)</sup>

## 감사 우선 롤아웃 (약 30일 권장)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화해 서명되지 않은 bind를 기록합니다 (이벤트 **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. 부분 CBT 적용 및 텔레메트리를 위해 DC GPO `LDAP server channel binding token requirements` = **When Supported**로 설정합니다. 먼저 레거시 클라이언트와의 호환성을 확인하세요.<sup>[[1]](#references)</sup>
3. Directory Service 이벤트를 모니터링합니다:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow 바인드(signing 비준수).
   - **3074/3075** – 실패하거나 CBT를 생략할 LDAPS 바인드(2019/2022에서는 KB4520412와 위의 2단계가 필요).
4. 별도로 변경 사항을 적용합니다:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (클라이언트).
   - `LDAP server signing requirements` = **Require signing** (DC) **또는** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP 채널 바인딩 및 LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 채널 바인딩 및 Signing 요구 사항](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 완화 업데이트](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing 비활성화 → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
