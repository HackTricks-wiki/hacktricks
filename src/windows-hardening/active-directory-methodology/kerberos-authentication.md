# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**다음의 훌륭한 post를 확인하세요:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 공격자를 위한 TL;DR
- Kerberos는 기본 AD auth protocol이며, 대부분의 lateral-movement chain이 Kerberos를 거칩니다.
- **세 가지 operator phase**를 기준으로 생각하세요:
- **AS-REQ / AS-REP** → password/hash/certificate를 사용해 **TGT**를 획득합니다. **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, **PKINIT**가 여기에 해당합니다.
- **TGS-REQ / TGS-REP** → TGT를 사용해 **service ticket**을 획득합니다. **Kerberoasting**, **S4U abuse**, **delegation abuse**, 그리고 대부분의 **ticket-forging tradecraft**가 여기서 중요해집니다.
- **AP-REQ / AP-REP** → service에 ticket을 제시합니다. **pass-the-ticket**과 service별 lateral movement가 여기서 발생합니다.
- 실전 cheatsheet(AS-REP/Kerberoasting, ticket forgery, delegation abuse 등)는 다음을 참조하세요:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 이 페이지는 **overview / “최근 변경 사항”** index로 사용한 다음, [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), 또는 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)의 전용 페이지로 이동하세요.

## 최신 attack notes (2024-2026)
- **RC4 hardening은 Kerberos 자체가 아니라 default를 변경했습니다** – 최근 DC hardening은 `msDS-SupportedEncryptionTypes`를 **명시적으로 설정하지 않은** account에 대해 **default assumed encryption types**를 적용하는 데 중점을 둡니다. 2026 rollout 이후 해당 account는 patched DC에서 점점 **AES-only**로 default 설정되므로, 무차별적인 `/rc4` Kerberoast 가정은 더 자주 실패합니다. 그러나 **명시적으로 RC4가 활성화된 service account는 여전히 뛰어난 offline-crack target**입니다.
- **PAC validation enforcement는 forged ticket에 중요합니다** – 2024 PAC-signature hardening으로 인해 **golden/diamond/sapphire/extraSID-style abuse**에는 더욱 현실적인 PAC data와 올바른 signing context가 필요합니다. 패치되지 않은 domain이나 compatibility/audit-style deployment 상태로 유지된 domain은 여전히 더 취약한 target입니다.
- **Certificate-based Kerberos는 두 차례 변경되었습니다**:
- **Strong certificate binding**(KB5014754 timeline)은 fully enforced environment에서 부정확한 certificate-to-account mapping의 신뢰성을 낮춥니다.
- **CVE-2025-26647**은 **altSecID / SKI certificate mapping**에 대한 또 다른 hardening layer를 추가했습니다. DC가 패치되지 않았거나, 여전히 auditing 상태이거나, NTAuth validation을 명시적으로 우회하고 있다면 pass-the-certificate / shadow-credential 후속 abuse는 여전히 더 실용적입니다.
- **Cross-domain / cross-forest delegation abuse는 여전히 매우 유효합니다** – Windows는 최신 cross-realm **S4U2Self/S4U2Proxy** flow를 지원하므로, 다른 domain의 writable delegation attribute는 여전히 가치가 있습니다. 일반적으로 blocker는 protocol support가 아니라 tooling fidelity와 trust/policy 세부 사항입니다.
- **Recursive multi-domain RBCD는 운영 측면에서 중요합니다** – 3개 이상의 domain으로 구성된 forest에서는 **S4U2Self/S4U2Proxy**가 trust referral을 통해 recursive하게 동작할 수 있으며, **SPN-less** abuse에는 최종 **`S4U2Self+U2U`** hop과 RC4-dependent ticket handling이 필요할 수 있습니다. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요.
- **Windows Server 2025는 dMSA migration logic을 통해 새로운 Kerberos-adjacent attack surface를 도입했습니다.** 2025 domain에서 OU 또는 service-account object에 대한 delegated rights가 보이면 “또 다른 gMSA”로 취급하지 말고 전용 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)를 확인하세요.

## 최신 domain에서의 빠른 operator 점검

Kerberos attack path를 선택하기 전에 다음 네 가지 질문에 빠르게 답하세요:

1. **어떤 account가 여전히 RC4-friendly한가?**
2. **어떤 user가 pre-auth를 요구하지 않는가?**
3. **어떤 object가 delegation abuse를 노출하는가?**
4. **domain의 어느 부분이 최근 hardening을 적용할 만큼 충분히 최신인가?**
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
- **interesting SPN accounts are explicitly RC4-capable**인 경우 Kerberoasting는 여전히 저렴하고 빠릅니다.
- 대부분의 service accounts에 **명시적인 etype 설정이 없는 경우**, 업데이트된 2026 DC에서는 **AES-only** 동작을 예상하고 더 느린 offline cracking 또는 다른 경로를 계획해야 합니다.
- **RBCD / KCD / unconstrained delegation**이 존재하는 경우 S4U가 brute-force보다 더 효과적인 경우가 많습니다.
- **certificate auth**가 사용되는 경우, 실패한 PKINIT 경로가 항상 해당 cert가 쓸모없다는 의미는 아니라는 점을 기억해야 합니다. 많은 환경에서 동일한 cert가 여전히 **Schannel/LDAPS** abuse에 작동합니다([AD Certificates / PKINIT abuse](ad-certificates.md)).

## 공격 계획을 변경하는 일반적인 Kerberos 오류
- **`KDC_ERR_ETYPE_NOTSUPP`** → 대상 account 또는 DC가 요청한 encryption type을 사용하지 않습니다. RC4 only로 계속 재시도하지 말고 **AES keys**를 제공하거나 **AES** roast material을 요청해야 합니다.
- **`KRB_AP_ERR_MODIFIED`** → **잘못된 service key**, **잘못된 SPN**을 사용하고 있거나, 실제로 복호화하는 service account와 일치하지 않는 forged ticket을 사용하고 있을 가능성이 높습니다.
- **`KRB_AP_ERR_SKEW`** → 시간이 맞지 않습니다. 다른 문제를 debug하기 전에 DC와 시간을 동기화해야 합니다.
- S4U / delegation flow 중 **`KDC_ERR_BADOPTION`** → 대개 **sensitive/not-delegable users**, 잘못된 delegation model 또는 non-forwardable S4U2Self ticket을 **RBCD**만 허용하는 상황에서 **classic KCD**로 수행하려는 경우를 의미합니다.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
