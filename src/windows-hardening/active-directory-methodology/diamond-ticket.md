# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticket처럼**, diamond ticket은 **어떤 사용자로든 어떤 서비스에 접근하는 데** 사용할 수 있는 TGT입니다. golden ticket은 오프라인에서 완전히 위조되며, 해당 도메인의 krbtgt 해시로 암호화한 다음 사용을 위해 로그온 세션에 전달됩니다. 도메인 컨트롤러는 자신이 정상적으로 발급한 TGT를 추적하지 않으므로, 자체 krbtgt 해시로 암호화된 TGT를 기꺼이 받아들입니다.<sup>[[1]](#references)</sup>

golden ticket 사용을 탐지하는 일반적인 기법은 두 가지입니다.

- 이에 대응하는 AS-REQ가 없는 TGS-REQ를 찾습니다.
- Mimikatz의 기본 10년 수명처럼 비정상적인 값을 가진 TGT를 찾습니다.

**diamond ticket은 DC가 발급한 정상적인 TGT의 필드를 수정해 만듭니다.** 도메인의 krbtgt 해시로 **TGT를 요청**하고, 이를 **복호화**한 다음, 티켓에서 원하는 필드를 **수정하고 다시 암호화**합니다. 이렇게 하면 golden ticket의 **앞서 언급한 두 가지 단점을 극복할 수 있습니다**.<sup>[[1]](#references)</sup>

- TGS-REQ 앞에 AS-REQ가 있습니다.
- TGT는 DC가 발급했으므로 도메인의 Kerberos 정책에 따른 올바른 세부 정보를 모두 포함합니다. golden ticket에서도 이를 정확하게 위조할 수 있지만, 더 복잡하고 실수할 가능성이 있습니다.

### 요구 사항 및 워크플로

- **암호화 자료**: TGT를 복호화하고 다시 서명할 krbtgt AES256 키(권장) 또는 NTLM 해시.
- **정상적인 TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`를 사용하거나 메모리에서 티켓을 내보내서 획득합니다.
- **컨텍스트 데이터**: 대상 사용자 RID, 그룹 RID/SID, 그리고 (선택적으로) LDAP에서 가져온 PAC 속성.
- **서비스 키** (서비스 티켓을 다시 만들 계획인 경우에만): 가장할 서비스 SPN의 AES 키.

1. AS-REQ를 통해 제어 중인 사용자에 대한 TGT를 획득합니다. (Rubeus `/tgtdeleg`은 자격 증명 없이 클라이언트가 Kerberos GSS-API 교환을 수행하도록 유도하므로 편리합니다.)
2. 반환된 TGT를 krbtgt 키로 복호화하고 PAC 속성(사용자, 그룹, 로그온 정보, SID, 디바이스 클레임 등)을 수정합니다.
3. 동일한 krbtgt 키로 티켓을 다시 암호화하고 서명한 다음, 현재 로그온 세션에 주입합니다(`kerberos::ptt`, `Rubeus.exe ptt` 등).
4. 선택적으로, 유효한 TGT blob과 대상 서비스 키를 제공해 서비스 티켓에 대해서도 같은 과정을 반복하면 네트워크상에서 더 은밀하게 동작할 수 있습니다.

### Rubeus 트레이드크래프트 업데이트 (2024+)

Huntress의 최근 작업으로 Rubeus의 `diamond` 액션이 현대화되었습니다. 이전에는 golden/silver ticket에서만 사용할 수 있었던 `/ldap` 및 `/opsec` 개선 사항을 이식했습니다. 이제 `/ldap`은 LDAP를 조회하고 SYSVOL을 마운트해 실제 PAC 컨텍스트와 계정/그룹 속성, Kerberos/암호 정책(예: `GptTmpl.inf`)을 가져옵니다. `/opsec`은 2단계 사전 인증 교환을 수행하고 AES만 허용하며 현실적인 KDCOptions를 적용해 AS-REQ/AS-REP 흐름을 Windows와 일치시킵니다. 이를 통해 PAC 필드 누락이나 정책과 일치하지 않는 수명처럼 눈에 띄는 지표가 크게 줄어듭니다.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (선택적으로 `/ldapuser` 및 `/ldappassword` 포함)는 AD와 SYSVOL을 쿼리해 대상 사용자의 PAC 정책 데이터를 미러링합니다.
- `/opsec`는 Windows와 유사한 AS-REQ 재시도를 강제하고, 노이즈가 많은 플래그를 0으로 설정하며 AES256만 사용합니다.
- `/tgtdeleg`는 피해자의 평문 비밀번호나 NTLM/AES 키를 건드리지 않으면서도 복호화 가능한 TGT를 반환합니다.

### 서비스 티켓 재구성

Rubeus의 같은 업데이트에는 TGS blob에 diamond 기법을 적용하는 기능이 추가되었습니다. `diamond`에 **base64로 인코딩된 TGT**(`asktgt`, `/tgtdeleg` 또는 이전에 위조한 TGT에서 획득), **서비스 SPN**, **서비스 AES 키**를 제공하면 KDC를 건드리지 않고도 그럴듯한 서비스 티켓을 생성할 수 있습니다. 이는 사실상 더 은밀한 silver ticket입니다.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

이 workflow는 service account key를 이미 제어하고 있고(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 덤프한 경우), 새로운 AS/TGS 트래픽을 발생시키지 않으면서 AD 정책, 타임라인, PAC 데이터와 완벽하게 일치하는 일회성 TGS를 만들고 싶을 때 이상적입니다.<sup>[[3]](#references)</sup>

### Sapphire 스타일 PAC 교체(2025)

최근 등장한 변형으로, **sapphire ticket**이라고도 불리는 이 방식은 Diamond의 "real TGT" 기반과 **S4U2self+U2U**를 결합해 권한이 높은 PAC를 탈취한 뒤 자신의 TGT에 삽입합니다. 추가 SID를 만들어내는 대신, `sname`이 권한이 낮은 요청자를 대상으로 하는 고권한 사용자용 U2U S4U2self ticket을 요청합니다. 이때 KRB_TGS_REQ에는 요청자의 TGT가 `additional-tickets`에 포함되고 `ENC-TKT-IN-SKEY`가 설정되므로, 해당 사용자의 키로 service ticket을 복호화할 수 있습니다. 그런 다음 권한이 높은 PAC를 추출해 정식 TGT에 끼워 넣고 krbtgt key로 다시 서명합니다.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket의 `ticketer.py`는 이제 `-impersonate` + `-request`를 통한 sapphire 지원을 제공합니다(live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate`는 username 또는 SID를 받으며, `-request`는 티켓을 복호화/패치하기 위해 실시간 사용자 creds와 krbtgt key material(AES/NTLM)이 필요합니다.

이 변형을 사용할 때 주의해야 할 주요 OPSEC 징후:<sup>[[5]](#references)</sup>

- TGS-REQ에는 `ENC-TKT-IN-SKEY`와 `additional-tickets`(victim TGT)가 포함됩니다. 일반 트래픽에서는 드문 조합입니다.
- `sname`은 종종 요청 사용자와 일치하며(self-service access), Event ID 4769에는 caller와 target이 같은 SPN/user로 표시됩니다.
- client computer는 같지만 CNAMES가 다른 4768/4769 항목 쌍이 예상됩니다(low-priv requester와 privileged PAC owner).

### OPSEC 및 탐지 참고 사항

- 기존 hunter 휴리스틱(TGS without AS, 수십 년에 걸친 lifetime)은 golden tickets에도 여전히 적용되지만, diamond tickets는 주로 **PAC content 또는 group mapping이 불가능해 보일 때** 드러납니다. 자동 비교에서 위조를 즉시 탐지하지 않도록 logon hours, user profile paths, device IDs 등 모든 PAC field를 채우세요.<sup>[[3]](#references)</sup>
- **groups/RIDs를 과도하게 추가하지 마세요**. `512`(Domain Admins)와 `519`(Enterprise Admins)만 필요하다면 거기서 멈추고, 대상 계정이 AD의 다른 곳에서도 그 그룹에 속하는 것이 타당한지 확인하세요. 과도한 `ExtraSids`는 눈에 띕니다.
- Sapphire-style swaps는 U2U 흔적을 남깁니다. `ENC-TKT-IN-SKEY` + `additional-tickets` 조합, 4769에서 사용자를 가리키는 `sname`(대개 requester), 그리고 위조된 티켓에서 비롯된 후속 4624 logon이 이에 해당합니다. no-AS-REQ 간극만 찾지 말고 이 field들을 연관 분석하세요.<sup>[[5]](#references)</sup>
- Microsoft는 CVE-2026-20833으로 인해 **RC4 service ticket 발급을 단계적으로 중단**하기 시작했습니다. KDC에서 AES-only etypes를 강제하면 도메인 보안이 강화되고 diamond/sapphire tooling과도 일치합니다(`/opsec`은 이미 AES를 강제함). 위조된 PAC에 RC4를 섞으면 점점 더 눈에 띄게 됩니다.<sup>[[6]](#references)</sup>
- Splunk의 Security Content project는 diamond tickets용 attack-range telemetry와 *Windows Domain Admin Impersonation Indicator* 같은 detection을 배포합니다. 이 detection은 비정상적인 Event ID 4768/4769/4624 시퀀스와 PAC group 변경을 연관 분석합니다. 해당 dataset을 재생하거나(또는 위 명령으로 직접 생성하여) SOC의 T1558.001 대응 범위를 검증하면, 회피할 구체적인 alert logic도 파악할 수 있습니다.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
