# AD CS 도메인 지속성

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 에서 공유된 도메인 지속성 기술의 요약입니다**. 자세한 내용은 해당 문서를 확인하세요.

## 도난당한 CA 인증서를 이용한 인증서 위조 (Golden Certificate) - DPERSIST1

인증서가 CA 인증서인지 어떻게 알 수 있나요?

다음 조건들이 충족되면 인증서가 CA 인증서임을 판단할 수 있습니다:

- 인증서는 CA 서버에 저장되어 있으며, 개인 키는 머신의 DPAPI로 보호되거나 운영 체제가 지원하는 경우 TPM/HSM 같은 하드웨어로 보호됩니다.
- 인증서의 Issuer 및 Subject 필드가 CA의 distinguished name과 일치합니다.
- CA 인증서에만 "CA Version" 확장(extension)이 존재합니다.
- 인증서에는 Extended Key Usage (EKU) 필드가 없습니다.

이 인증서의 개인 키를 추출하려면 CA 서버에서 제공되는 GUI를 통해 `certsrv.msc` 도구를 사용하는 것이 지원되는 방법입니다. 그럼에도 불구하고 이 인증서는 시스템에 저장된 다른 인증서들과 구별되지 않으므로, [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)와 같은 방법으로도 추출할 수 있습니다.

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
> 인증서 위조 대상 사용자는 프로세스가 성공하려면 Active Directory에서 활성 상태이며 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정에 대한 인증서 위조는 효과가 없습니다.

이 위조된 인증서는 지정된 종료 날짜까지 그리고 루트 CA 인증서가 유효한 한(보통 5년에서 **10+년**) **유효**합니다. 또한 **machines**에 대해서도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 한 **어떤 도메인 머신에서든 지속성을 유지할 수 있습니다**.\
더욱이, 이 방법으로 생성된 **인증서들은** CA가 이를 인지하지 못하기 때문에 **폐기될 수 없습니다**.

### Strong Certificate Mapping Enforcement(2025+) 하에서의 운영

2025년 2월 11일 이후(KB5014754 배포 후)부터 domain controllers는 certificate mappings에 대해 기본적으로 **Full Enforcement**를 적용합니다. 실무적으로 이는 위조된 인증서가 다음 중 하나를 만족해야 함을 의미합니다:

- 타깃 계정에 대한 강한 바인딩을 포함해야 합니다(예: SID security extension), 또는
- 대상 객체의 `altSecurityIdentities` 속성에 강력하고 명시적인 매핑이 설정되어 있어야 합니다.

지속성을 확보하는 신뢰할 수 있는 접근법은 도난당한 Enterprise CA에 체인된 위조 인증서를 발행한 다음 피해자 principal에 강력한 명시적 매핑을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
참고
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
이 기능은 ForgeCert를 이용해 동적으로 인증서를 생성하는 앞서 설명한 방법과 함께 사용할 때 특히 관련성이 높습니다.

> Post-2025 매핑 고려사항: NTAuth에 rogue CA를 배치하는 것은 발급 CA에 대한 신뢰만 설정합니다. DC가 **Full Enforcement** 상태일 때 로그온에 leaf 인증서를 사용하려면, 해당 leaf에는 SID security extension이 포함되어 있거나 대상 객체에 강력한 명시적 매핑(예: `altSecurityIdentities`의 Issuer+Serial)이 있어야 합니다. 자세한 내용은 {{#ref}}account-persistence.md{{#endref}}를 참조하세요.

## Malicious Misconfiguration - DPERSIST3

AD CS 구성요소의 **security descriptor 수정**을 통한 **persistence** 기회는 많습니다. "[Domain Escalation](domain-escalation.md)" 섹션에 설명된 수정들은 도메인에서 권한이 상승된 공격자가 악의적으로 구현할 수 있습니다. 여기에는 다음과 같은 민감한 구성요소에 대한 "control rights"(예: WriteOwner/WriteDACL/etc.) 추가가 포함됩니다:

- **CA 서버의 AD computer** 객체
- **CA 서버의 RPC/DCOM 서버**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 내의 모든 **하위 AD 객체 또는 컨테이너**(예: Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체 등)
- 기본적으로 또는 조직에 의해 **AD CS 제어 권한이 위임된 AD 그룹**(예: 내장된 Cert Publishers 그룹 및 해당 멤버)

악의적 구현의 예로는 도메인에서 **elevated permissions**를 가진 공격자가 기본 **`User`** certificate template에 **`WriteOwner`** 권한을 추가하고, 그 권한의 주체(principal)를 자신으로 설정하는 경우가 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유권을 자신으로 변경합니다. 그 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면, 요청 시 Subject Alternative Name을 제공할 수 있게 됩니다. 이후 공격자는 해당 **템플릿**으로 **enroll**하여 대체 이름으로 **domain administrator** 이름을 선택하고, 획득한 인증서를 DA로서의 인증에 사용할 수 있습니다.

공격자가 장기적인 도메인 persistence를 위해 설정할 수 있는 실용적 옵션들(전체 세부사항 및 탐지 방법은 {{#ref}}domain-escalation.md{{#endref}} 참조):

- 요청자에게서 SAN을 허용하는 CA 정책 플래그(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이는 ESC1 유사 경로를 계속해서 악용 가능하게 유지합니다.
- 인증 기능 발급을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- 수비자가 정리를 시도할 경우 rogue 발급자를 지속적으로 재도입하기 위해 `NTAuthCertificates` 객체나 CA 컨테이너를 제어.

> [!TIP]
> KB5014754 이후 강화된 환경에서는 이러한 오구성(misconfigurations)을 명시적인 강력 매핑(`altSecurityIdentities`)과 결합하면, DC가 강력 매핑을 적용할 때에도 발급되거나 위조된 인증서를 계속 사용할 수 있습니다.

## References

- Microsoft KB5014754 – Windows 도메인 컨트롤러의 인증서 기반 인증 변경사항(강화 일정 및 강력 매핑). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
