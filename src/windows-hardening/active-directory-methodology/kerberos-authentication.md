# Kerberos 인증

{{#include ../../banners/hacktricks-training.md}}

**다음의 훌륭한 포스트를 확인하세요:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## 공격자를 위한 TL;DR
- Kerberos는 기본 AD 인증 프로토콜이며, 대부분의 lateral-movement 체인이 이를 거치게 됩니다.
- **세 가지 operator 단계**로 생각하세요:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → password/hash/certificate를 사용해 **TGT**를 획득합니다. **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, **PKINIT**가 여기에 해당합니다.
- **TGS-REQ / TGS-REP** → TGT를 사용해 **service tickets**를 획득합니다. **Kerberoasting**, **S4U abuse**, **delegation abuse**, 그리고 대부분의 **ticket-forging tradecraft**가 여기서 중요해집니다.
- **AP-REQ / AP-REP** → service에 ticket을 제시합니다. **pass-the-ticket**과 service별 lateral movement가 여기서 수행됩니다.
- 실습용 cheatsheet(AS-REP/Kerberoasting, ticket forgery, delegation abuse 등)는 다음을 참조하세요:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 이 페이지는 **overview / “최근 변경 사항”** index로 사용한 다음, [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), 또는 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)의 전용 페이지로 이동하세요.

## 최신 공격 참고 사항 (2024-2026)
- **RC4 hardening은 기본값을 변경했을 뿐 Kerberos 자체를 변경한 것은 아닙니다** – 최근 DC hardening은 `msDS-SupportedEncryptionTypes`를 명시적으로 설정하지 않은 계정에 대해 **기본으로 가정되는 encryption types**에 초점을 맞춥니다. 2026년 rollout 이후, 이러한 계정은 patched DC에서 점점 **AES-only**를 기본값으로 사용하므로, 무작정 `/rc4`를 사용하는 Kerberoast 가정이 더 자주 실패합니다. 그러나 **명시적으로 RC4가 활성화된 service accounts는 여전히 뛰어난 offline-crack 대상**입니다.<sup>[[1]](#references)</sup>
- **PAC validation enforcement는 forged tickets에 중요합니다** – 2024년 PAC-signature hardening으로 인해 **golden/diamond/sapphire/extraSID-style abuses**에는 더 현실적인 PAC data와 올바른 signing context가 필요합니다. Unpatched domains 또는 compatibility/audit-style deployments 상태로 남아 있는 도메인은 여전히 더 취약한 대상입니다.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos는 두 차례 변경되었습니다**:<sup>[[2]](#references)</sup>
- **Strong certificate binding**(KB5014754 timeline)은 완전히 enforced된 환경에서 부정확한 certificate-to-account mappings의 신뢰성을 떨어뜨립니다.
- **CVE-2025-26647**은 **altSecID / SKI certificate mappings**에 대한 추가 hardening layer를 도입했습니다. DC가 unpatched 상태이거나 여전히 auditing 중이거나 NTAuth validation을 명시적으로 우회하는 경우, pass-the-certificate / shadow-credential 후속 abuse는 여전히 더 실용적입니다.
- **Cross-domain / cross-forest delegation abuse는 여전히 매우 유효합니다** – Windows는 최신 cross-realm **S4U2Self/S4U2Proxy** flows를 지원하므로, 다른 도메인의 writable delegation attributes는 여전히 가치가 있습니다. 일반적인 blocker는 protocol support가 아니라 tooling fidelity와 trust/policy details입니다.
- **Recursive multi-domain RBCD는 운영 측면에서 중요합니다** – 3개 이상의 도메인이 있는 forest에서는 **S4U2Self/S4U2Proxy**가 trust referrals를 통해 재귀적으로 동작할 수 있으며, **SPN-less** abuse에는 최종 **`S4U2Self+U2U`** hop과 RC4-dependent ticket handling이 필요할 수 있습니다. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요.<sup>[[4]](#references)</sup>
- **Windows Server 2025는 dMSA migration logic을 통해 새로운 Kerberos-adjacent attack surface를 도입했습니다.** 2025 도메인에서 OU 또는 service-account objects에 대한 delegated rights가 보이면 이를 “그저 또 다른 gMSA”로 취급하지 말고 전용 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)를 확인하세요.

## 최신 도메인에서의 빠른 operator 점검

Kerberos attack path를 선택하기 전에 다음 네 가지 질문에 빠르게 답하세요:

1. **어떤 계정이 아직 RC4-friendly 상태인가?**
2. **어떤 사용자가 pre-auth를 요구하지 않는가?**
3. **어떤 object가 delegation abuse를 노출하는가?**
4. **도메인의 어느 부분이 최신 hardening을 적용할 만큼 새로운가?**
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
- **interesting SPN accounts are explicitly RC4-capable**인 경우 Kerberoasting은 계속 저렴하고 빠릅니다.
- 대부분의 service accounts에 **명시적인 etype configuration이 없는 경우**, 업데이트된 2026 DC에서는 **AES-only** 동작을 예상하고 더 느린 offline cracking 또는 다른 경로를 계획해야 합니다.
- **RBCD / KCD / unconstrained delegation**이 존재한다면 S4U가 brute-force보다 효과적인 경우가 많습니다.
- **certificate auth**가 사용되는 경우, PKINIT 경로가 실패했다고 해서 cert가 항상 쓸모없는 것은 아니라는 점을 기억해야 합니다. 많은 환경에서 동일한 cert가 여전히 **Schannel/LDAPS** abuse에 사용됩니다([AD Certificates / PKINIT abuse](ad-certificates.md)).

## 공격 계획을 변경하는 일반적인 Kerberos 오류
- **`KDC_ERR_ETYPE_NOTSUPP`** → 대상 account 또는 DC가 요청한 encryption type을 사용하지 않습니다. RC4 only로 계속 재시도하지 말고 **AES keys**를 제공하거나 **AES** roast material을 요청해야 합니다.
- **`KRB_AP_ERR_MODIFIED`** → **잘못된 service key**, **잘못된 SPN**, 또는 실제로 복호화하는 service account와 일치하지 않는 forged ticket을 사용하고 있을 가능성이 높습니다.
- **`KRB_AP_ERR_SKEW`** → 시간이 맞지 않습니다. 다른 문제를 debug하기 전에 DC와 시간을 동기화해야 합니다.
- S4U / delegation 흐름 중 **`KDC_ERR_BADOPTION`** → 대개 **sensitive/not-delegable users**, 잘못된 delegation model, 또는 **RBCD**에서만 non-forwardable S4U2Self ticket을 허용하는 상황에서 **classic KCD**를 시도하고 있음을 의미합니다.

## References
- [1] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
