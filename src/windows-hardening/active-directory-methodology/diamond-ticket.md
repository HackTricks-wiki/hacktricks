# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **어떤 사용자로서든 어떤 서비스에 접근할 수 있습니다**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### 요구사항 및 워크플로우

- **암호화 자료**: TGT를 복호화하고 재서명하기 위한 krbtgt AES256 키(권장) 또는 NTLM hash.
- **정상 TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`로 획득하거나 메모리에서 티켓을 내보내어 얻은 것.
- **컨텍스트 데이터**: 대상 사용자 RID, 그룹 RIDs/SIDs, 및 (선택적으로) LDAP에서 가져온 PAC 속성들.
- **서비스 키** (서비스 티켓을 재발행하려는 경우에만): 위조할 서비스 SPN의 AES 키.

1. 제어 가능한 사용자로 AS-REQ을 통해 TGT를 얻습니다. Rubeus의 `/tgtdeleg`는 자격증명 없이 클라이언트가 Kerberos GSS-API 절차를 수행하도록 강제하므로 편리합니다.
2. 반환된 TGT를 krbtgt 키로 복호화하고 PAC 속성(사용자, 그룹, 로그온 정보, SIDs, 장치 클레임 등)을 패치합니다.
3. 동일한 krbtgt 키로 티켓을 다시 암호화/서명하고 현재 로그온 세션에 주입합니다 (`kerberos::ptt`, `Rubeus.exe ptt` 등).
4. 선택적으로, 유선상에서 은밀함을 유지하기 위해 유효한 TGT blob과 대상 서비스 키를 제공하여 서비스 티켓에 대해 동일한 프로세스를 반복할 수 있습니다.

### 업데이트된 Rubeus 기법 (2024+)

Huntress의 최근 작업으로 Rubeus 내부의 `diamond` 액션이 modernized 되었고, 이전에 golden/silver 티켓에서만 존재하던 `/ldap` 및 `/opsec` 개선사항이 이식되었습니다. `/ldap`는 이제 AD에서 정확한 PAC 속성(사용자 프로필, logon hours, sidHistory, 도메인 정책 등)을 자동으로 채워주며, `/opsec`는 두 단계의 pre-auth 시퀀스를 수행하고 AES-only 암호화를 강제하여 AS-REQ/AS-REP 흐름을 Windows client와 구분할 수 없게 만듭니다. 이는 빈 장치 ID나 비현실적인 유효 기간과 같은 명확한 지표를 크게 줄여줍니다.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`)는 대상 사용자의 PAC 정책 데이터를 미러링하기 위해 AD와 SYSVOL을 쿼리합니다.
- `/opsec`는 Windows-유사 AS-REQ 재시도를 강제하며 노이즈가 큰 플래그를 0으로 초기화하고 AES256을 고정적으로 사용합니다.
- `/tgtdeleg`는 피해자의 평문 비밀번호나 NTLM/AES 키에 직접 접근하지 않으면서도 복호화 가능한 TGT를 반환합니다.

### Service-ticket recutting

같은 Rubeus 업데이트는 diamond technique을 TGS blobs에 적용하는 기능을 추가했습니다. `diamond`에 **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**를 제공하면 KDC를 건드리지 않고도 현실적인 서비스 티켓을 생성할 수 있습니다 — 사실상 더 은밀한 silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
이 워크플로우는 이미 서비스 계정 키(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 덤프한)를 보유하고 있으며 새로운 AS/TGS 트래픽을 발생시키지 않고 AD 정책, 타임라인, PAC 데이터와 정확히 일치하는 일회성 TGS를 생성하려는 경우에 이상적입니다.

### OPSEC 및 탐지 노트

- 전통적인 헌터 휴리스틱(AS 없이 얻은 TGS, 수십 년짜리 수명)은 golden tickets에도 여전히 적용되지만, diamond tickets는 주로 **PAC 내용이나 그룹 매핑이 불가능해 보일 때** 드러납니다. 자동 비교에서 위조를 즉시 탐지하지 않도록 모든 PAC 필드(로그온 시간, 사용자 프로필 경로, 장치 ID 등)를 채우세요.
- **그룹/RIDs를 과도하게 할당하지 마세요**. 만약 `512` (Domain Admins)와 `519` (Enterprise Admins)만 필요하다면 거기서 멈추고 대상 계정이 AD의 다른 곳에서 해당 그룹에 그럴듯하게 속해 있는지 확인하세요. 과도한 `ExtraSids`는 드러납니다.
- Splunk의 Security Content 프로젝트는 diamond tickets용 attack-range 텔레메트리와 *Windows Domain Admin Impersonation Indicator* 같은 탐지 규칙을 배포합니다. 이 규칙은 비정상적인 Event ID 4768/4769/4624 시퀀스와 PAC 그룹 변경을 연관시킵니다. 해당 데이터셋을 재생하거나(또는 위 명령으로 자체 생성하면) T1558.001에 대한 SOC 커버리지를 검증하고 회피를 위한 구체적인 경보 로직을 얻는 데 도움이 됩니다.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
