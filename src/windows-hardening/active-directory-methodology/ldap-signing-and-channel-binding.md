# LDAP Signing 및 Channel Binding 강화

{{#include ../../banners/hacktricks-training.md}}

## 중요한 이유

LDAP relay/MITM을 사용하면 공격자가 바인드를 Domain Controllers로 전달하여 인증된 컨텍스트를 획득할 수 있습니다. 서버 측의 다음 두 가지 제어 기능은 이러한 경로를 차단합니다.

- **LDAP Channel Binding (CBT)**은 LDAPS 바인드를 특정 TLS 터널에 연결하여 서로 다른 채널 간의 relay/replay를 차단합니다.
- **LDAP Signing**은 무결성이 보호된 LDAP 메시지를 강제하여 변조와 대부분의 unsigned relay를 방지합니다.

**빠른 offensive 확인**: `netexec ldap <dc> -u user -p pass`와 같은 tools는 서버 설정 상태를 출력합니다. `(signing:None)` 및 `(channel binding:Never)`가 표시되면 Kerberos/NTLM **relays to LDAP**이 가능합니다(예: KrbRelayUp를 사용하여 RBCD를 위한 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 작성하고 administrators를 impersonate).<sup>[[4]](#references)</sup>

**Server 2025 DCs**에는 새로운 GPO(**LDAP server signing requirements Enforcement**)가 도입되었으며, **Not Configured** 상태로 두면 기본적으로 **Require Signing**으로 설정됩니다. enforcement를 방지하려면 해당 policy를 명시적으로 **Disabled**로 설정해야 합니다.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch(2017)는 Extended Protection for Authentication support를 추가합니다.<sup>[[3]](#references)</sup>
- **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” telemetry를 추가합니다.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: failures를 기록하지만 차단하지 않음)
- `Always` (enforce: 유효한 CBT가 없는 LDAPS bind를 거부)<sup>[[1]](#references)</sup>
- **Audit**: 다음을 표시하려면 **When Supported**로 설정합니다.
- **3074** – enforcement가 적용되었다면 LDAPS bind가 CBT validation에 실패했을 상황을 나타냅니다.
- **3075** – LDAPS bind에서 CBT data가 누락되었으며 enforcement가 적용되었다면 거부되었을 상황을 나타냅니다.
- (Event **3039**는 이전 builds에서도 CBT failures를 계속 나타냅니다.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients가 CBT를 전송하면 **Always**로 설정합니다. **LDAPS**에서만 적용되며 raw 389에는 적용되지 않습니다.<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows의 default인 `Negotiate signing`과 비교).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default는 `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: legacy policy를 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정합니다(Not Configured = 기본적으로 enforced; 이를 방지하려면 `Disabled`로 설정).<sup>[[1]](#references)</sup>
- **Compatibility**: Windows **XP SP3+**만 LDAP signing을 지원합니다. enforcement가 활성화되면 이전 시스템은 작동하지 않습니다.

## Audit-first rollout (recommended ~30 days)

1. unsigned binds(Event **2889**)를 기록하도록 각 DC에서 LDAP interface diagnostics를 활성화합니다:<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements`을 **When Supported**로 설정하여 CBT telemetry를 시작합니다.<sup>[[1]](#references)</sup>
3. Directory Service 이벤트를 모니터링합니다:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (signing 비준수).
- **3074/3075** – 실패하거나 CBT를 생략할 LDAPS binds (2019/2022에서는 KB4520412 및 위의 2단계가 필요).
4. 별도의 변경 사항으로 적용합니다:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **또는** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 참고 자료

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
