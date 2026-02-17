# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. 골든 티켓과 마찬가지로, 다이아몬드 티켓은 어떤 사용자로서든 어떤 서비스든 접근할 수 있는 TGT이다.

A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash. golden ticket는 완전히 오프라인에서 위조되며 해당 도메인의 krbtgt 해시로 암호화되어 사용을 위해 로그온 세션에 주입된다. 도메인 컨트롤러는 자신이 합법적으로 발급한 TGT를 추적하지 않기 때문에, 자신의 krbtgt 해시로 암호화된 TGT를 기꺼이 받아들인다.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

golden ticket 사용을 탐지하는 일반적인 방법 두 가지는 다음과 같다:

- AS-REQ에 해당하는 항목이 없는 TGS-REQ를 찾아라.
- Mimikatz의 기본 10년 유효기간처럼 비정상적으로 긴 값 등을 가진 TGT를 찾아라.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

**diamond ticket**은 DC가 발급한 합법적인 TGT의 필드를 수정하여 만든다. 방법은 TGT를 요청하고, 도메인의 krbtgt 해시로 이를 복호화한 다음, 티켓의 원하는 필드를 수정하고 다시 암호화하는 것이다. 이렇게 하면 golden ticket의 앞서 언급한 두 가지 단점을 극복할 수 있다:

- TGS-REQ에는 선행하는 AS-REQ가 존재한다.
- 해당 TGT는 DC가 발급했기 때문에 도메인의 Kerberos 정책에 따른 모든 올바른 세부정보를 포함한다. 이러한 정보들은 golden ticket으로 정확히 위조할 수 있지만, 그 과정은 더 복잡하고 실수할 여지가 크다.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

### 요구사항 및 워크플로우

- **암호화 자료**: TGT를 복호화하고 재서명하기 위한 krbtgt AES256 키(권장) 또는 NTLM 해시.
- **정상적인 TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`로 획득하거나 메모리에서 티켓을 내보내어 얻는다.
- **컨텍스트 데이터**: 대상 사용자 RID, 그룹 RID/SID, (선택적으로) LDAP에서 가져온 PAC 속성들.
- **서비스 키** (서비스 티켓을 다시 발급할 계획일 경우에만): 가장하여 접근할 서비스 SPN의 AES 키.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

1. AS-REQ를 통해 제어하는 사용자에 대한 TGT를 획득한다 (Rubeus의 `/tgtdeleg`은 자격증명 없이 클라이언트가 Kerberos GSS-API 절차를 수행하도록 강제하기 때문에 편리하다).
2. 반환된 TGT를 krbtgt 키로 복호화하고 PAC 속성(사용자, 그룹, logon 정보, SIDs, device claims 등)을 패치한다.
3. 동일한 krbtgt 키로 티켓을 재암호화/서명하고 현재 로그온 세션에 주입한다 (`kerberos::ptt`, `Rubeus.exe ptt` 등).
4. 선택적으로, 유효한 TGT blob과 대상 서비스 키를 제공하여 네트워크 상에서 더 은밀하게 행동하기 위해 서비스 티켓에 대해 같은 과정을 반복할 수 있다.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.

### Rubeus 최신 기법 (2024+)

Huntress의 최신 작업은 Rubeus 내부의 `diamond` 액션을 현대화했으며, 이전에는 golden/silver tickets에만 존재하던 `/ldap` 및 `/opsec` 개선사항을 이식했다. `/ldap`은 이제 AD에서 직접 정확한 PAC 속성(사용자 프로필, logon hours, sidHistory, 도메인 정책 등)을 자동으로 채워 넣고, `/opsec`은 2단계 사전 인증(pre-auth) 시퀀스를 수행하고 AES 전용 암호화를 강제함으로써 AS-REQ/AS-REP 흐름을 Windows 클라이언트와 구별하기 어렵게 만든다. 이는 빈 device ID나 비현실적인 유효 기간 같은 명백한 지표를 크게 줄여준다.
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
- `/ldap` (선택적으로 `/ldapuser` & `/ldappassword` 포함) AD와 SYSVOL을 쿼리하여 대상 사용자의 PAC 정책 데이터를 복제합니다.
- `/opsec`은 Windows 스타일의 AS-REQ 재시도를 강제하고, 노이즈를 유발하는 플래그를 0으로 설정하며 AES256을 사용합니다.
- `/tgtdeleg`은 피해자의 평문 비밀번호나 NTLM/AES 키에 손대지 않으면서도 복호화 가능한 TGT를 반환합니다.

### 서비스 티켓 재가공

동일한 Rubeus 업데이트는 diamond technique을 TGS blobs에 적용할 수 있는 기능을 추가했습니다. `diamond`에 **base64-encoded TGT**(`asktgt`, `/tgtdeleg`, 또는 이전에 위조한 TGT에서 가져옴), **service SPN**, 그리고 **service AES key**를 제공하면, KDC를 건드리지 않고 현실감 있는 service tickets를 생성할 수 있습니다 — 사실상 더 은밀한 silver ticket입니다.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
이 워크플로우는 이미 service account key(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 덤프한 상태)를 제어하고 있으며, 새로운 AS/TGS 트래픽을 발생시키지 않고 AD 정책, 타임라인 및 PAC 데이터에 완벽히 일치하는 일회성 TGS를 발급하려는 경우에 이상적입니다.

### Sapphire-style PAC swaps (2025)

새로운 변형으로 때때로 **sapphire ticket**이라 불리는 방법은 Diamond의 "real TGT" 기반에 **S4U2self+U2U**를 결합하여 권한 있는 PAC를 탈취해 자신의 TGT에 삽입합니다. 추가 SIDs를 만들어내는 대신, 높은 권한을 가진 사용자에 대해 U2U S4U2self 티켓을 요청하고 해당 PAC를 추출한 뒤 정당한 TGT에 결합한 다음 krbtgt 키로 재서명합니다. U2U가 `ENC-TKT-IN-SKEY`를 설정하기 때문에, 결과적으로 네트워크 상의 흐름은 합법적인 user-to-user 교환처럼 보입니다.

Minimal Linux-side reproduction with Impacket's patched `ticketer.py` (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
이 변형을 사용할 때 주요 OPSEC 징후:

- TGS-REQ는 `ENC-TKT-IN-SKEY` 및 `additional-tickets` (피해자 TGT)를 포함합니다 — 정상 트래픽에서는 드뭅니다.
- `sname`은 종종 요청 사용자와 동일합니다(셀프 서비스 액세스)이고 Event ID 4769는 호출자와 대상이 동일한 SPN/사용자로 표시됩니다.
- 동일한 클라이언트 컴퓨터에서 발생하지만 다른 CNAMES가 있는 4768/4769 쌍을 예상하세요(저권한 요청자 vs. 권한 있는 PAC 소유자).

### OPSEC & detection notes

- 전통적인 hunter heuristics (TGS without AS, decade-long lifetimes)은 여전히 golden tickets에 적용되지만, diamond tickets는 주로 **PAC content or group mapping이 불가능해 보일 때** 드러납니다. 자동 비교에서 위조를 즉시 감지하지 않도록 모든 PAC 필드(logon hours, user profile paths, device IDs)를 채우세요.
- **Do not oversubscribe groups/RIDs**. `512` (Domain Admins)와 `519` (Enterprise Admins)만 필요하다면 거기까지만 하고 대상 계정이 AD 내 다른 곳에서 그 그룹들에 합리적으로 속해 있는지 확인하세요. 과도한 `ExtraSids`는 티가 납니다.
- Sapphire-style swaps는 U2U 지문을 남깁니다: 4769에서 `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname`, 그리고 위조된 티켓에서 시작된 후속 4624 로그온. no-AS-REQ 간극만 찾지 말고 이 필드들을 상관관계 분석하세요.
- Microsoft는 CVE-2026-20833 때문에 **RC4 service ticket issuance**를 단계적으로 중단하기 시작했습니다; KDC에서 AES-only etypes를 강제하면 도메인 강화와 diamond/sapphire 툴링과의 정합성을 동시에 제공합니다(/opsec는 이미 AES를 강제합니다). 위조된 PAC에 RC4를 섞으면 점점 더 눈에 띄게 됩니다.
- Splunk의 Security Content 프로젝트는 diamond tickets에 대한 attack-range 텔레메트리와 *Windows Domain Admin Impersonation Indicator* 같은 탐지(비정상적인 Event ID 4768/4769/4624 시퀀스와 PAC 그룹 변경을 상관관계 분석)를 배포합니다. 해당 데이터셋을 재생하거나(또는 위 명령으로 자체 생성하면) T1558.001에 대한 SOC 커버리지를 검증하는 데 도움이 되며 회피할 구체적인 알림 로직을 제공합니다.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
