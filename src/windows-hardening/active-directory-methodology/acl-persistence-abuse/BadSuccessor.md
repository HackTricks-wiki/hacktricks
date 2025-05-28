# Active Directory ACLs/ACEs 악용

{{#include ../../../banners/hacktricks-training.md}}

## 개요

위임된 관리 서비스 계정(**dMSAs**)는 **Windows Server 2025**와 함께 도입된 새로운 AD 주체 유형입니다. 이는 레거시 서비스 계정을 대체하도록 설계되어, 이전 계정의 서비스 주체 이름(SPN), 그룹 멤버십, 위임 설정 및 심지어 암호화 키를 자동으로 복사하는 원클릭 “마이그레이션”을 허용하여 애플리케이션이 원활하게 전환하고 Kerberoasting 위험을 제거합니다.

Akamai 연구원들은 단일 속성인 **`msDS‑ManagedAccountPrecededByLink`**가 dMSA가 “계승”하는 레거시 계정을 KDC에 알려준다는 것을 발견했습니다. 공격자가 해당 속성을 쓸 수 있고 **`msDS‑DelegatedMSAState` → 2**로 전환할 수 있다면, KDC는 선택한 피해자의 모든 SID를 **상속하는 PAC**를 기꺼이 생성하여 dMSA가 도메인 관리자 포함 모든 사용자를 가장할 수 있게 합니다.

## dMSA란 정확히 무엇인가?

* **gMSA** 기술 위에 구축되었지만 새로운 AD 클래스 **`msDS‑DelegatedManagedServiceAccount`**로 저장됩니다.
* **옵트인 마이그레이션**을 지원합니다: `Start‑ADServiceAccountMigration`을 호출하면 dMSA가 레거시 계정에 연결되고, 레거시 계정에 `msDS‑GroupMSAMembership`에 대한 쓰기 권한이 부여되며, `msDS‑DelegatedMSAState`가 1로 전환됩니다.
* `Complete‑ADServiceAccountMigration` 후, 대체된 계정은 비활성화되고 dMSA는 완전히 기능을 하게 됩니다; 이전에 레거시 계정을 사용했던 모든 호스트는 자동으로 dMSA의 비밀번호를 가져올 수 있는 권한을 부여받습니다.
* 인증 중에 KDC는 **KERB‑SUPERSEDED‑BY‑USER** 힌트를 삽입하여 Windows 11/24H2 클라이언트가 dMSA로 투명하게 재시도하도록 합니다.

## 공격 요구 사항
1. **최소 하나의 Windows Server 2025 DC**가 필요하여 dMSA LDAP 클래스와 KDC 로직이 존재해야 합니다.
2. **OU에 대한 객체 생성 또는 속성 쓰기 권한**(모든 OU) – 예: `Create msDS‑DelegatedManagedServiceAccount` 또는 단순히 **Create All Child Objects**. Akamai는 실제 환경의 91%가 비관리자에게 이러한 “무해한” OU 권한을 부여한다고 발견했습니다.
3. Kerberos 티켓을 요청하기 위해 도메인에 가입된 호스트에서 도구(PowerShell/Rubeus)를 실행할 수 있는 능력.
* 피해자 사용자에 대한 제어는 필요하지 않으며, 공격은 대상 계정을 직접 건드리지 않습니다.*

## 단계별: BadSuccessor* 권한 상승

1. **제어할 수 있는 dMSA 찾기 또는 생성하기**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

당신이 쓸 수 있는 OU 내에서 객체를 생성했기 때문에, 자동으로 모든 속성을 소유하게 됩니다.

2. **두 개의 LDAP 쓰기로 “완료된 마이그레이션” 시뮬레이션**:
- `msDS‑ManagedAccountPrecededByLink = DN`을 피해자의 것으로 설정합니다 (예: `CN=Administrator,CN=Users,DC=lab,DC=local`).
- `msDS‑DelegatedMSAState = 2`로 설정합니다 (마이그레이션 완료).

**Set‑ADComputer, ldapmodify** 또는 **ADSI Edit**와 같은 도구가 작동하며, 도메인 관리자 권한이 필요하지 않습니다.

3. **dMSA에 대한 TGT 요청** — Rubeus는 `/dmsa` 플래그를 지원합니다:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

반환된 PAC에는 이제 SID 500(관리자) 및 도메인 관리자/엔터프라이즈 관리자 그룹이 포함됩니다.

## 모든 사용자 비밀번호 수집

정상적인 마이그레이션 중에 KDC는 새로운 dMSA가 **전환 전에 이전 계정에 발급된 티켓을 복호화**할 수 있도록 해야 합니다. 활성 세션을 중단하지 않기 위해, 현재 키와 이전 키를 **`KERB‑DMSA‑KEY‑PACKAGE`**라는 새로운 ASN.1 블롭에 배치합니다.

우리의 가짜 마이그레이션이 dMSA가 피해자를 계승한다고 주장하기 때문에, KDC는 피해자의 RC4-HMAC 키를 **이전 키** 목록에 성실히 복사합니다 – dMSA가 “이전” 비밀번호를 가졌던 적이 없더라도 말입니다. 이 RC4 키는 소금이 없으므로, 사실상 피해자의 NT 해시가 되어 공격자에게 **오프라인 크래킹 또는 “패스-더-해시”** 능력을 제공합니다.

따라서 수천 명의 사용자를 대량으로 연결하면 공격자가 해시를 “대규모로” 덤프할 수 있게 되어 **BadSuccessor가 권한 상승 및 자격 증명 손상 원시 기능이 됩니다**.

## 도구

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## 참고 문헌

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
