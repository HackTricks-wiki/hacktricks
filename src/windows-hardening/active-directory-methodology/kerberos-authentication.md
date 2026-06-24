# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**다음의 훌륭한 글도 확인하세요:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 공격자용 TL;DR
- Kerberos는 기본 AD auth protocol이며; 대부분의 lateral-movement 체인은 이를 사용합니다.
- **세 가지 operator phase**로 생각하세요:
- **AS-REQ / AS-REP** → **TGT**를 얻기 위해 password/hash/certificate를 사용합니다. 여기에는 **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, 그리고 **PKINIT**가 있습니다.
- **TGS-REQ / TGS-REP** → **service tickets**를 얻기 위해 TGT를 사용합니다. 여기에는 **Kerberoasting**, **S4U abuse**, **delegation abuse**, 그리고 대부분의 **ticket-forging tradecraft**가 포함됩니다.
- **AP-REQ / AP-REP** → ticket을 service에 제시합니다. 여기에서 **pass-the-ticket**과 service-specific lateral movement가 발생합니다.
- 실전용 cheatsheets(AS-REP/Kerberoasting, ticket forgery, delegation abuse 등)는 다음을 보세요:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 이 페이지를 **overview / “최근에 무엇이 바뀌었는지”** 인덱스로 사용한 뒤, [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), 또는 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) 전용 페이지로 이동하세요.

## 최신 attack notes (2024-2026)
- **RC4 hardening은 기본값을 바꿨을 뿐, Kerberos 자체를 바꾼 것은 아닙니다** – modern DC hardening은 `msDS-SupportedEncryptionTypes`를 명시적으로 설정하지 않은 account에 대해 **기본적으로 가정되는 encryption types**에 초점을 맞춥니다. 2026 rollout 이후, 이러한 account는 patched DC에서 점점 **AES-only**로 기본 설정되므로, 무작정 `/rc4` Kerberoast를 가정하면 실패하는 경우가 더 많아집니다. 그러나 **명시적으로 RC4가 활성화된 service accounts는 여전히 훌륭한 offline-crack 대상**입니다.
- **PAC validation enforcement는 forged tickets에 중요합니다** – 2024 PAC-signature hardening은 **golden/diamond/sapphire/extraSID-style abuses**가 더 현실적인 PAC data와 올바른 signing context를 필요로 하게 만듭니다. unpatched domain 또는 compatibility/audit-style deployment로 남아 있는 domain은 여전히 더 취약한 대상입니다.
- **Certificate-based Kerberos는 두 번 바뀌었습니다**:
- **Strong certificate binding**(KB5014754 timeline)은 완전히 enforced된 환경에서 느슨한 certificate-to-account mapping의 신뢰성을 더 낮춥니다.
- **CVE-2025-26647**는 **altSecID / SKI certificate mappings** 주변에 또 하나의 hardening layer를 추가했습니다. DC가 unpatched 상태이거나, 여전히 auditing 중이거나, 명시적으로 NTAuth validation을 우회하는 경우에는 pass-the-certificate / shadow-credential 후속 abuse가 여전히 더 실용적입니다.
- **cross-domain / cross-forest delegation abuse는 여전히 매우 활발합니다** – Windows는 modern cross-realm **S4U2Self/S4U2Proxy** flow를 지원하므로, 다른 domain에서 writable delegation attribute는 여전히 가치가 있습니다. 보통의 걸림돌은 protocol support가 아니라 tooling fidelity와 trust/policy 세부사항입니다.
- **Windows Server 2025는 **dMSA** migration logic를 통해 새로운 Kerberos-adjacent attack surface를 도입했습니다. 2025 domain에서 OU 또는 service-account object에 대한 delegated rights를 보면, 이를 “그냥 또 다른 gMSA”로 취급하지 말고 전용 [BadSuccessor 페이지](acl-persistence-abuse/BadSuccessor.md)를 확인하세요.

## modern domain에서의 빠른 operator check

Kerberos attack path를 선택하기 전에, 다음 네 가지를 빠르게 답하세요:

1. **어떤 accounts가 여전히 RC4-friendly인가?**
2. **어떤 users가 pre-auth를 요구하지 않는가?**
3. **어떤 objects가 delegation abuse를 노출하는가?**
4. **domain의 어떤 부분이 최근 hardening을 적용할 만큼 새 것인가?**
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
Practical interpretation:
- **흥미로운 SPN 계정이 명시적으로 RC4-capable**라면, Kerberoasting은 여전히 저렴하고 빠릅니다.
- 대부분의 서비스 계정에 **명시적 etype configuration이 없으면**, 업데이트된 2026 DCs에서는 **AES-only** 동작을 예상하고 더 느린 offline cracking 또는 다른 경로를 계획하세요.
- **RBCD / KCD / unconstrained delegation**가 있으면, S4U가 종종 brute-force보다 더 유리합니다.
- **certificate auth**가 사용 중이라면, 실패한 PKINIT path가 항상 해당 cert가 쓸모없다는 뜻은 아닙니다. 많은 환경에서 같은 cert가 여전히 **Schannel/LDAPS** abuse에 동작합니다([AD Certificates / PKINIT abuse](ad-certificates.md) 참조).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → 대상 계정 / DC가 요청한 encryption type을 사용하지 않습니다. RC4만으로 재시도하지 말고, **AES keys**를 제공하거나 대신 **AES** roast material을 요청하세요.
- **`KRB_AP_ERR_MODIFIED`** → 아마도 **잘못된 service key**, **잘못된 SPN**, 또는 실제로 이를 복호화하는 service account와 일치하지 않는 forged ticket을 사용한 것입니다.
- **`KRB_AP_ERR_SKEW`** → 시간이 맞지 않습니다. 다른 무엇보다 먼저 DC와 시간을 동기화하세요.
- **S4U / delegation flows 중 `KDC_ERR_BADOPTION`** → 자주 **sensitive/not-delegable users**, 잘못된 delegation model, 또는 **RBCD**만 non-forwardable S4U2Self ticket을 허용하는데도 **classic KCD**를 시도하고 있다는 뜻입니다.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
