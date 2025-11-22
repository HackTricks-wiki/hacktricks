# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### 요구사항 및 작업 흐름

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### 업데이트된 Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`)는 AD와 SYSVOL을 쿼리하여 대상 사용자의 PAC 정책 데이터를 미러링합니다.
- `/opsec`는 Windows와 유사한 AS-REQ 재시도를 강제하며, 노이즈가 되는 플래그를 0으로 설정하고 AES256을 사용합니다.
- `/tgtdeleg`는 대상자의 평문 비밀번호나 NTLM/AES 키에 손대지 않고도 복호화 가능한 TGT를 반환합니다.

### Service-ticket 재가공

동일한 Rubeus 업데이트는 diamond 기법을 TGS blobs에 적용하는 기능을 추가했습니다. `diamond`에 **base64-encoded TGT**(from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**를 제공하면 KDC를 건드리지 않고 현실적인 service tickets를 생성할 수 있습니다 — 사실상 더 은밀한 silver ticket입니다.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
이 워크플로우는 이미 서비스 계정 키(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 덤프한 경우)를 보유하고 있으며, 새로운 AS/TGS 트래픽을 발생시키지 않고 AD 정책, 유효 기간, 및 PAC 데이터에 완벽히 일치하는 일회성 TGS를 생성하려는 경우에 이상적입니다.

### OPSEC & detection notes

- 전통적인 hunter heuristics (AS 없이 발급된 TGS, 수십 년 단위의 수명)는 여전히 golden tickets에 적용되지만, diamond tickets은 주로 **PAC 내용이나 그룹 매핑이 불가능해 보일 때** 드러납니다. 자동 비교에서 즉시 위조를 표시하지 않도록 모든 PAC 필드(로그온 시간, 사용자 프로필 경로, 장치 ID)를 채우세요.
- **groups/RIDs를 과도하게 할당하지 마세요**. 필요한 것이 `512` (Domain Admins)와 `519` (Enterprise Admins)뿐이라면 거기서 멈추고 대상 계정이 AD의 다른 곳에서 그 그룹에 그럴듯하게 속해 있는지 확인하세요. 과도한 `ExtraSids`는 티가 납니다.
- Splunk의 Security Content 프로젝트는 diamond tickets에 대한 attack-range telemetry와 *Windows Domain Admin Impersonation Indicator* 같은 탐지 규칙을 배포합니다. 이 규칙은 비정상적인 Event ID 4768/4769/4624 시퀀스와 PAC 그룹 변경을 상관시키는 방식입니다. 해당 데이터셋을 재생하거나(위 명령으로 자체 생성하면) SOC의 T1558.001 커버리지를 검증하고 회피할 구체적인 알림 로직을 얻는 데 도움이 됩니다.

## 참고자료

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
