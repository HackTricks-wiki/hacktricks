# LDAP Signing 및 Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## 중요한 이유

LDAP relay/MITM 공격은 인증을 domain controller로 전달해 인증된 LDAP context를 얻습니다. [name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)에서 더 광범위한 공격 흐름을 다룹니다. 다음 두 관련 제어는 이러한 공격 경로를 줄입니다.

- **LDAP channel binding (CBT)**은 적용 가능한 인증을 LDAPS에서 사용하는 TLS 서버 인증서/channel에 바인딩하여, 서로 다른 channel 간 relay를 어렵게 합니다.
- **LDAP signing**은 SASL LDAP bind에 무결성 보호를 요구합니다. 기밀성을 추가하지는 않으므로 LDAP 내용도 암호화해야 한다면 TLS를 사용하세요.<sup>[[2]](#references)</sup>

**빠른 보안 상태 확인**: `netexec ldap <dc> -u user -p pass`와 같은 도구는 관찰된 signing 및 channel-binding 정책을 보고합니다. `(signing:None)` 및 `(channel binding:Never)`는 제어가 빠져 있음을 나타내지만, relay 성공 여부는 캡처된 인증 유형, EPA 동작, 계정 권한, 대상 프로토콜 및 relay 보호 기능에 따라 달라집니다. relay된 principal에 필요한 권한이 있으면 KrbRelayUp 같은 도구로 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 수정하고, resource-based constrained delegation (RBCD)을 구성한 뒤, 그 delegation 경로를 이용해 권한이 높은 principal을 가장할 수 있습니다.<sup>[[4]](#references)</sup>

**Server 2025 DC**에는 새 GPO(**LDAP server signing requirements Enforcement**)가 도입되며, **Not Configured** 상태에서는 기본값이 **Require Signing**입니다. 적용을 피하려면 해당 정책을 명시적으로 **Disabled**로 설정해야 합니다.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS 전용)

- **요구 사항**:
  - CVE-2017-8563 패치(2017)는 Extended Protection for Authentication 지원을 추가합니다.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022)는 LDAPS CBT “what-if” 원격 분석을 추가합니다.<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (기본값, CBT 없음)
  - `When Supported` (부분 적용: CBT를 지원하는 클라이언트는 유효한 token을 제공해야 합니다. CBT를 지원하지 않는 클라이언트는 계속 bind할 수 있으며, 감사 이벤트가 생성됩니다.)
  - `Always` (적용: 유효한 CBT가 없는 LDAPS bind를 거부합니다.)<sup>[[1]](#references)</sup>
- **감사**: **When Supported**로 설정하면 다음 이벤트가 기록됩니다.
  - **3074** – 적용 중이었다면 CBT 검증 실패로 LDAPS bind가 실패했을 상황입니다.
  - **3075** – LDAPS bind에 CBT 데이터가 없어 적용 중이었다면 거부됐을 상황입니다.
  - (이전 빌드에서는 이벤트 **3039**도 여전히 CBT 실패를 나타냅니다.)<sup>[[1]](#references)[[2]](#references)</sup>
- **적용**: LDAPS 클라이언트가 CBT를 전송하기 시작하면 **Always**로 설정하세요. **LDAPS**에서만 유효하며 raw 389에는 적용되지 않습니다.<sup>[[1]](#references)</sup>

`When Supported`는 감사 전용 설정이 아닙니다. CBT를 지원하는 클라이언트의 CBT를 검증하면서, CBT를 지원하지 않는 클라이언트는 허용합니다. [Microsoft 정책 참조](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)에서 버전에 따른 기본값을 확인할 수 있습니다. LDAP signing은 LDAP/389에서 적용 대상인 bind에 적용되며, channel binding은 TLS로 보호되는 LDAP 인증에 적용됩니다.


## LDAP Signing

- **클라이언트 GPO**: `Network security: LDAP client signing requirements` = `Require signing` (현대 Windows의 기본값인 `Negotiate signing`과 다름).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - 레거시: `Domain controller: LDAP server signing requirements` = `Require signing` (기본값은 `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: 레거시 정책은 `None`으로 두고 `LDAP server signing requirements Enforcement` = `Enabled`로 설정합니다 (`Not Configured`이면 기본적으로 적용되며, 적용을 피하려면 `Disabled`로 설정).<sup>[[1]](#references)</sup>
- **호환성**: simple bind 또는 signing되지 않은 SASL bind를 사용하는 비 Windows 어플라이언스와 애플리케이션을 조사하세요. Microsoft는 지원 중인 Windows 버전에서의 지원을 문서화하고 있습니다. 레거시 클라이언트 호환성에 관한 설명은 XP 버전 기준으로 단순화하지 말고 실제 클라이언트 스택을 기준으로 확인해야 합니다.<sup>[[2]](#references)</sup>

## Relay 경로 및 signed-SASL 재인증

**signing만** 요구하는 경우, channel binding이 적용되지 않으면 LDAPS로 relay가 여전히 가능할 수 있습니다. TLS가 전송 무결성을 제공하기 때문입니다. **channel binding만** 요구하는 경우, 일반 LDAP에는 바인딩할 TLS channel이 없습니다. relay된 identity에 필요한 권한이 있으면 TCP 389에서 인증한 뒤 TLS가 필요한 작업에 StartTLS를 사용할 수 있습니다. 두 설정을 모두 적용하면 이러한 일반적인 대안은 차단되지만, 패치되지 않은 domain controller에서는 아래 취약점이 여전히 동작했습니다.<sup>[[5]](#references)</sup>

### Relay된 Bind 뒤에 LDAP 작업 추가하기

취약한 Windows Server 2016–2025 domain controller에서는 먼저 TCP 389에서 identity X로 **signed NTLM SASL LDAP connection**을 설정합니다. 이때 session key를 알고 있는 자격 증명을 사용하거나, 허용되는 경우 anonymous NTLM SASL context를 사용합니다. 그런 다음 identity Y가 **SMB**를 통해 relay 대상으로 인증하도록 유도합니다. Y의 NTLM NEGOTIATE와 DC의 CHALLENGE를 X의 기존 LDAP connection에서 GSS-SPNEGO Bind 요청으로 전달합니다. Windows SMB 클라이언트는 `NTLMSSP_NEGOTIATE_SIGN`을 설정하므로 결과 LDAP bind에는 signed SASL layer가 필요합니다. HTTP/WebDAV에서 시작된 교환에는 일반적으로 이 flag가 없으므로 여기서는 동일하게 사용할 수 없습니다.<sup>[[5]](#references)</sup>

Y가 NTLM AUTHENTICATE를 보낼 때 **서로 다른 두 LDAP 메시지를 하나의 길이 접두사가 붙은 SASL record에** 넣습니다. 첫 번째는 해당 응답을 담은 BindRequest이고, 그 다음은 ModifyRequest입니다. X의 알려진 key로 전체 record에 서명합니다. 취약한 DC는 X를 기준으로 record를 검증하고 Bind를 완료한 다음, connection의 authorization을 Y로 전환하고, record를 Y의 key로 다시 검증하지 않은 채 나머지 ModifyRequest를 Y의 권한으로 실행합니다. 이 과정에서 Y의 password나 session key가 노출되지는 않으며, 이후 X가 서명한 record는 실패합니다. `msDS-AllowedToActOnBehalfOfOtherIdentity`에 대한 RBCD 쓰기나 `msDS-KeyCredentialLink`에 대한 shadow-credential 쓰기에도 Y가 대상 object에 대한 권한을 보유해야 합니다. [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), 그리고 relay된 DC machine account의 경우 [DCSync](dcsync.md)를 참조하세요.<sup>[[5]](#references)</sup>

이는 **일반 LDAP** 우회이며 LDAPS channel-binding 우회가 아닙니다. LDAPS에서는 TLS가 connection을 보호하고, Windows는 이 record-stacking 경로에 필요한 X-key NTLM SASL signing layer를 설정하지 않습니다. TCP 389을 사용할 수 없다면 이 기법을 TCP 636에 그대로 적용할 수 없습니다. 2026년 10월 보안 업데이트는 Bind가 connection identity를 변경한 뒤 남은 데이터를 폐기하여 동일 record에서 작업이 실행되는 것을 방지합니다.<sup>[[5]](#references)</sup> KB5126646은 Windows Server 2025 업데이트이며, 영향을 받는 다른 Server 버전에는 각기 다른 KB 번호가 있습니다.<sup>[[7]](#references)</sup>

연구자가 만든 [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)는 이 작업 흐름을 위해 수정된 `ntlmrelayx.py`를 래핑합니다. 이 도구에는 **SMB** coercion source, LDAP signing/security-context API를 제공하는 고정된 Impacket tree (PyPI Impacket 0.13.1로는 부족), 그리고 초기 signed bind를 위한 공격자 제어 계정이 필요합니다. RBCD 쓰기에는 victim object의 DN과 제어 중인 delegating computer의 SID를 지정합니다. 다른 허용된 쓰기에는 `-attribute`와 함께 `-value` 또는 `-value-hex`를 사용하세요. relay 측의 `FAILED` 메시지를 ModifyRequest 실패의 증거로 간주하지 말고, 도구가 별도로 수행하는 signed read-back으로 결과를 확인하세요.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

SMB authentication은 별도로 트리거하세요. 한 가지 coercion surface는 [privileged NTLM authentication 강제](printers-spooler-service-abuse.md)를, 다른 방법은 [relay 개요](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)를 참조하세요. 도구의 명령과 구현은 해당 저장소에 문서화되어 있습니다.<sup>[[6]](#references)</sup>

## 감사 우선 롤아웃(권장 기간: 약 30일)

1. 각 DC에서 LDAP 인터페이스 진단을 활성화해 서명되지 않은 바인드를 기록합니다(Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. DC GPO `LDAP server channel binding token requirements`를 **When Supported**로 설정해 부분적인 CBT 적용 및 telemetry를 수행합니다. 먼저 레거시 클라이언트와의 호환성을 확인하세요.<sup>[[1]](#references)</sup>
3. Directory Service 이벤트를 모니터링합니다:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow bind(서명 미준수).
   - **3074/3075** – 실패하거나 CBT가 누락될 LDAPS bind(KB4520412 및 위 2단계가 필요).
4. 별도 변경 사항으로 적용합니다:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (클라이언트).
   - `LDAP server signing requirements` = **Require signing** (DC) **또는** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP 채널 바인딩 및 LDAP 서명](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 채널 바인딩 및 서명 요구 사항](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 완화 업데이트](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP 서명 비활성화 → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – 서명, 봉인, 릴레이: NTLM 스타일](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo 개념 증명](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server 릴리스 정보](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
