# AD CS 도메인 지속성

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 에서 공유된 도메인 지속성 기법들의 요약입니다. 자세한 내용은 해당 문서를 확인하세요.**

## Forging Certificates with Stolen CA Certificates - DPERSIST1

어떻게 해당 인증서가 CA 인증서인지 알 수 있을까요?

다음 조건들이 충족되면 인증서가 CA 인증서임을 판별할 수 있습니다:

- 인증서는 CA 서버에 저장되며, 해당 머신의 DPAPI로 보호되거나 운영체제가 지원하면 TPM/HSM 같은 하드웨어로 보호된 개인키와 함께 저장됩니다.
- 인증서의 Issuer 및 Subject 필드가 CA의 distinguished name과 일치합니다.
- "CA Version" extension이 오직 CA 인증서에만 존재합니다.
- 인증서에 Extended Key Usage (EKU) 필드가 없습니다.

이 인증서의 개인키를 추출하려면 CA 서버에서 내장 GUI를 통해 `certsrv.msc` 도구를 사용하는 것이 지원되는 방법입니다. 그럼에도 불구하고, 이 인증서는 시스템에 저장된 다른 인증서들과 본질적으로 다르지 않으므로 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)와 같은 방법을 사용해 추출할 수 있습니다.

인증서와 개인키는 또한 Certipy를 사용하여 다음 명령으로 얻을 수 있습니다:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 인증서와 개인 키를 `.pfx` 형식으로 확보한 후, [ForgeCert](https://github.com/GhostPack/ForgeCert) 같은 도구를 사용하여 유효한 인증서를 생성할 수 있습니다:
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
> 인증서 위조 대상 사용자는 프로세스가 성공하려면 Active Directory에서 활성 상태이며 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정에 대한 인증서 위조는 효과가 없습니다.

이 위조된 인증서는 지정된 종료 날짜까지 그리고 **루트 CA 인증서가 유효한 한** (보통 5년에서 **10년 이상**) **유효**합니다. 또한 **machines**에도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 동안 **any domain machine에서 persistence를 유지할 수 있습니다**.\
더욱이, 이 방법으로 생성된 **certificates generated**는 CA가 이를 인지하지 못하므로 **취소할 수 없습니다**.

### Strong Certificate Mapping Enforcement (2025+) 하에서의 운영

2025년 2월 11일( KB5014754 배포 이후)부터 도메인 컨트롤러는 인증서 매핑에 대해 기본적으로 **Full Enforcement**를 적용합니다. 실무적으로 이는 위조된 인증서가 다음 중 하나를 만족해야 함을 의미합니다:

- 대상 계정에 대한 강력한 바인딩을 포함할 것(예: SID security extension), 또는
- 대상 객체의 `altSecurityIdentities` 속성에 강력하고 명시적인 매핑과 짝을 이루고 있을 것.

지속성을 위한 신뢰할 수 있는 접근법은 도난당한 Enterprise CA에 체인된 위조 인증서를 발급한 다음 피해자 주체(victim principal)에 강력한 명시적 매핑을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- 취소(revocation)는 여기서 방어자에게 도움이 되지 않습니다: 위조된 인증서는 CA 데이터베이스에 알려져 있지 않으므로 취소될 수 없습니다.

## 악성 CA 인증서 신뢰 - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. **도메인 컨트롤러**에 의한 검증 과정은 인증하는 **certificate**의 Issuer 필드에 지정된 **CA**와 일치하는 항목이 `NTAuthCertificates` 객체에 있는지 확인하는 것입니다. 일치하는 항목이 발견되면 인증이 진행됩니다.

공격자가 이 AD 객체를 제어할 수 있다면 self-signed CA certificate를 `NTAuthCertificates` 객체에 추가할 수 있습니다. 일반적으로 이 객체를 수정할 권한은 **Enterprise Admin** 그룹 구성원과 **forest root’s domain**의 **Domain Admins** 또는 **Administrators**에게만 부여됩니다. 이들은 `certutil.exe`를 사용하여 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 명령으로 `NTAuthCertificates` 객체를 편집하거나, [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)을 사용할 수 있습니다.

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
이 기능은 ForgeCert를 사용해 동적으로 인증서를 생성하는 앞에서 설명한 방법과 함께 사용할 때 특히 관련성이 큽니다.

> Post-2025 매핑 고려사항: NTAuth에 rogue CA를 배치하면 발행 CA에 대한 신뢰만 설정됩니다. DC가 **Full Enforcement** 상태일 때 로그온용으로 leaf 인증서를 사용하려면, 해당 leaf에 SID 보안 확장이 포함되어 있거나 대상 객체에 강력한 명시적 매핑(예: Issuer+Serial을 `altSecurityIdentities`에 설정)이 있어야 합니다. 자세한 내용은 {{#ref}}account-persistence.md{{#endref}}를 참조하십시오.

## 악의적 잘못된 구성 - DPERSIST3

AD CS 구성요소의 보안 설명자(security descriptor)를 수정하여 **persistence**를 얻을 수 있는 기회는 많습니다. "[Domain Escalation](domain-escalation.md)" 섹션에 설명된 변경사항들은 도메인에서 권한이 상승된 공격자에 의해 악의적으로 구현될 수 있습니다. 여기에는 다음과 같은 민감한 구성요소에 대한 "control rights"(예: WriteOwner/WriteDACL/etc.) 추가가 포함됩니다:

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>** 내의 모든 **후손 AD 객체나 컨테이너**(예: Certificate Templates container, Certification Authorities container, `NTAuthCertificates` object 등)
- 조직이나 기본값으로 **AD CS를 제어하도록 위임된 AD 그룹**(예: 빌트인 Cert Publishers 그룹 및 해당 멤버들)

악의적 구현의 예로는 도메인에서 **권한이 상승된** 공격자가 기본 **`User`** certificate template에 대해 자신을 주체로 하여 **`WriteOwner`** 권한을 추가하는 상황이 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유권을 자신으로 변경합니다. 그 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면, 사용자가 요청 시 Subject Alternative Name을 제공할 수 있습니다. 이후 공격자는 해당 **template**로 **enroll**하여 alternative name으로 도메인 관리자 이름을 선택하고, 획득한 인증서를 DA로서 인증에 사용할 수 있습니다.

장기간 도메인 지속성 유지를 위해 공격자가 설정할 수 있는 실무적 설정들(전체 세부사항 및 탐지 방법은 {{#ref}}domain-escalation.md{{#endref}} 참조):

- 요청자(requesters)로부터 SAN을 허용하는 CA 정책 플래그(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이는 ESC1-like 경로를 계속 악용 가능하게 합니다.
- 인증 가능한 발급을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- 수비측이 정리 시도를 하더라도 rogue issuer를 지속적으로 재도입할 수 있도록 `NTAuthCertificates` 객체 또는 CA 컨테이너를 제어.

> [!TIP]
> KB5014754 이후 하드닝된 환경에서는 이러한 잘못된 구성에 명시적이고 강력한 매핑(`altSecurityIdentities`)을 결합하면, DC가 강력한 매핑을 적용하더라도 발급하거나 위조한 인증서를 계속 사용할 수 있습니다.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
