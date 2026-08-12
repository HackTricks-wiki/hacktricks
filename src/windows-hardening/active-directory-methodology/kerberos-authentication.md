# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

아래에 요약된 교환 과정을 프로토콜 수준에서 단계별로 확인하려면 Tarlogic의 Kerberos 문서를 참조하세요.<sup>[[3]](#references)</sup>

## 공격자를 위한 TL;DR
- Kerberos는 기본 AD auth 프로토콜이며, 대부분의 lateral-movement 체인은 Kerberos와 관련됩니다.
- **세 가지 operator 단계**로 생각하세요:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → password/hash/certificate를 사용해 **TGT**를 획득합니다. **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, **PKINIT**가 이 단계에 해당합니다.
- **TGS-REQ / TGS-REP** → TGT를 사용해 **service tickets**를 획득합니다. **Kerberoasting**, **S4U abuse**, **delegation abuse**, 그리고 대부분의 **ticket-forging tradecraft**가 이 단계에서 중요합니다.
- **AP-REQ / AP-REP** → service에 ticket을 제시합니다. **pass-the-ticket**과 service-specific lateral movement가 이 단계에서 수행됩니다.
- 실습용 cheatsheets(AS-REP/Kerberoasting, ticket forgery, delegation abuse 등)는 다음을 참조하세요:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 이 페이지를 **overview / “최근 변경 사항”** index로 사용한 다음, [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), 또는 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)의 전용 페이지로 이동하세요.

## 최신 attack notes (2024-2026)
- **RC4 hardening은 Kerberos 자체가 아니라 기본값을 변경했습니다** – 최신 DC hardening은 `msDS-SupportedEncryptionTypes`를 명시적으로 설정하지 않은 계정에 적용되는 **기본 암호화 유형**에 중점을 둡니다. 2026년 rollout 이후, 이러한 계정은 patched DC에서 점점 더 **AES-only**를 기본값으로 사용하므로, 무조건적인 `/rc4` Kerberoast 가정은 더 자주 실패합니다. 그러나 **명시적으로 RC4가 활성화된 service accounts는 여전히 우수한 offline-crack 대상**입니다.<sup>[[1]](#references)</sup>
- **PAC validation enforcement는 forged tickets에 중요합니다** – 2024년 PAC-signature hardening으로 인해 **golden/diamond/sapphire/extraSID-style abuses**에는 더 현실적인 PAC 데이터와 올바른 signing context가 필요합니다. 패치되지 않은 domain이나 compatibility/audit-style deployment 상태로 방치된 domain은 여전히 더 취약한 대상입니다.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos는 두 차례 변경되었습니다**:
- **Strong certificate binding** (KB5014754 timeline)은 완전히 enforcement된 환경에서 부정확한 certificate-to-account mapping의 신뢰성을 낮춥니다.
- **CVE-2025-26647**은 certificate의 Subject Key Identifier를 사용하는 `altSecurityIdentities` mapping에 또 다른 hardening 계층을 추가했습니다. 따라서 pass-the-certificate 및 관련 certificate-based 경로를 평가할 때는 patch level, enforcement 또는 audit state, 명시적 mapping configuration이 중요합니다.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> PKINIT의 경우 KDC는 certificate path도 검증하고, NTAuth store를 통해 issuer가 trusted 상태인지 확인합니다.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse는 여전히 유효합니다** – Windows는 최신 cross-realm **S4U2Self/S4U2Proxy** 흐름을 지원하므로, 다른 domain의 writable delegation attributes는 여전히 가치가 있습니다. 일반적인 blocker는 protocol support가 아니라 tooling fidelity와 trust/policy 세부 사항입니다.
- **Recursive multi-domain RBCD는 운영 측면에서 중요합니다** – 3개 이상의 domain이 있는 forest에서는 **S4U2Self/S4U2Proxy**가 trust referral을 통해 재귀적으로 동작할 수 있으며, **SPN-less** abuse에는 최종 **`S4U2Self+U2U`** hop과 RC4-dependent ticket handling이 필요할 수 있습니다. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요.<sup>[[4]](#references)</sup>
- **Windows Server 2025에는 delegated Managed Service Accounts (dMSAs)**와 해당 migration logic이 도입되었습니다. 2025 domain에서 OU 또는 service-account objects에 대한 delegated rights가 보이면 이를 “또 다른 gMSA”로 취급하지 말고 전용 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)를 확인하세요.<sup>[[7]](#references)</sup>

## 최신 domain에서 빠르게 확인할 항목

Kerberos attack path를 선택하기 전에 다음 네 가지 질문에 빠르게 답하세요:

1. **아직 RC4-friendly 상태인 accounts는 무엇인가?**
2. **pre-auth가 필요하지 않은 users는 누구인가?**
3. **어떤 objects가 delegation abuse를 허용하는가?**
4. **domain의 어느 부분이 최신 hardening을 적용할 만큼 새로운가?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
실무적 해석:
- **interesting SPN accounts가 명시적으로 RC4-capable인 경우**, Kerberoasting은 여전히 저렴하고 빠릅니다.
- 대부분의 service accounts에 **explicit etype configuration이 없는 경우**, 업데이트된 2026 DC에서는 **AES-only** 동작을 예상하고 더 느린 offline cracking 또는 다른 경로를 계획해야 합니다.
- **RBCD / KCD / unconstrained delegation**이 존재한다면, S4U가 brute-force보다 더 효과적인 경우가 많습니다.
- **certificate auth**가 사용되는 경우, 실패한 PKINIT 경로가 항상 해당 cert가 쓸모없다는 의미는 아니라는 점을 기억해야 합니다. 많은 환경에서 동일한 cert가 여전히 **Schannel/LDAPS** abuse에 작동합니다([AD Certificates / PKINIT abuse](ad-certificates.md) 참조).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → target account / DC가 요청한 encryption type을 사용하지 않습니다. RC4만 사용하여 재시도하지 말고, **AES keys**를 제공하거나 **AES** roast material을 대신 요청해야 합니다.
- **`KRB_AP_ERR_MODIFIED`** → **wrong service key**, **wrong SPN**, 또는 실제로 복호화하는 service account와 일치하지 않는 forged ticket을 가지고 있을 가능성이 높습니다.
- **`KRB_AP_ERR_SKEW`** → 시간이 맞지 않습니다. 다른 문제를 debug하기 전에 DC와 시간을 sync해야 합니다.
- S4U / delegation flows 중 발생하는 **`KDC_ERR_BADOPTION`** → 대개 **sensitive/not-delegable users**, 잘못된 delegation model, 또는 **RBCD**에서만 non-forwardable S4U2Self ticket을 허용하는데 **classic KCD**를 수행하려는 경우를 의미합니다.

## References
- [1] [Microsoft Learn - Kerberos에서 RC4 사용 감지 및 해결](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - 최신 Windows hardening 지침 및 주요 날짜](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos는 어떻게 작동하는가? - 이론](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Cross-Domain 및 Cross-Forest 환경에서 RBCD 악용하기: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754 certificate-based authentication 변경 사항](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos certificate mapping vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Delegated Managed Service Accounts 개요](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Smart-card certificate 요구 사항 및 KDC validation](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
