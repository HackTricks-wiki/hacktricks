# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이 내용은 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에 수록된 도메인 지속성(domain persistence) 기술의 요약입니다. 자세한 내용은 해당 문서를 확인하세요.**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

어떻게 해당 인증서가 CA 인증서인지 알 수 있나요?

다음 조건들이 충족되면 해당 인증서가 CA 인증서임을 판단할 수 있습니다:

- 인증서는 CA 서버에 저장되어 있으며, 개인 키는 운영체제가 지원할 경우 머신의 DPAPI 또는 TPM/HSM 같은 하드웨어로 보호됩니다.
- 인증서의 Issuer 및 Subject 필드가 CA의 distinguished name과 일치합니다.
- "CA Version" 확장 필드가 오직 CA 인증서들에만 존재합니다.
- 인증서에 Extended Key Usage (EKU) 필드가 없습니다.

이 인증서의 개인 키를 추출하려면 CA 서버에서 내장 GUI를 통해 `certsrv.msc` 도구를 사용하는 것이 지원되는 방법입니다. 그럼에도 불구하고 이 인증서는 시스템에 저장된 다른 인증서들과 다르지 않으므로, [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)와 같은 방법으로 추출할 수 있습니다.

인증서와 개인 키는 Certipy를 사용해 다음 명령으로 얻을 수도 있습니다:
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

이 위조된 인증서는 지정된 만료일까지 그리고 루트 CA 인증서가 유효한 동안(보통 5년에서 10년 이상) **유효**합니다. 또한 **도메인 컴퓨터(머신)** 에도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 한 **어떤 도메인 컴퓨터에서든 지속성을 유지할 수 있습니다**.\
더욱이, 이 방법으로 **생성된 인증서들은** CA가 이를 알지 못하기 때문에 **폐기(또는 철회)할 수 없습니다**.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- 대상 계정에 대한 강력한 바인딩을 포함해야 합니다(예: SID security extension), 또는
- 대상 객체의 `altSecurityIdentities` 속성에 강력하고 명시적인 매핑이 있어야 합니다.

지속성을 위한 신뢰할 수 있는 방법은 도난당한 Enterprise CA에 체인된 위조 인증서를 발행한 다음 피해자 주체(victim principal)에 강력하고 명시적인 매핑을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
노트
- SID security extension를 포함하는 forged certificates를 제작할 수 있다면, 이는 Full Enforcement 하에서도 암묵적으로 매핑됩니다. 그렇지 않으면 명시적인 강한 매핑을 사용하는 것이 좋습니다. 명시적 매핑에 대한 자세한 내용은 [account-persistence](account-persistence.md)를 참조하세요.
- 이 경우 revocation은 방어자에게 도움이 되지 않습니다: 위조된 인증서는 CA 데이터베이스에 등록되어 있지 않으므로 폐기할 수 없습니다.

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
이 기능은 ForgeCert를 이용해 동적으로 인증서를 생성하는 앞서 설명된 방법과 함께 사용할 때 특히 관련성이 큽니다.

> Post-2025 매핑 관련 고려사항: NTAuth에 rogue CA를 등록하는 것은 발급 CA에 대한 신뢰만 설정합니다. DC가 **Full Enforcement** 상태일 때 로그인에 leaf certificates를 사용하려면, 해당 leaf는 SID security extension을 포함해야 하거나 대상 객체에 대한 강력한 명시적 매핑(예: Issuer+Serial이 `altSecurityIdentities`에 있음)이 있어야 합니다. 자세한 내용은 {{#ref}}account-persistence.md{{#endref}} 참조.

## 악의적 잘못된 구성 - DPERSIST3

AD CS 구성요소의 security descriptor를 수정하여 **persistence**를 확보할 수 있는 기회는 매우 많습니다. "[Domain Escalation](domain-escalation.md)" 섹션에서 설명된 수정사항들은 도메인 내에서 권한이 상승된 공격자에 의해 악의적으로 구현될 수 있습니다. 여기에는 다음과 같은 민감한 구성요소에 "control rights"(예: WriteOwner/WriteDACL/etc.)를 추가하는 것이 포함됩니다:

- **CA server’s AD computer** 객체
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**의 하위 AD 객체나 컨테이너(예: Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체 등)
- **AD groups delegated rights to control AD CS**(기본 Cert Publishers 그룹 및 그 멤버 등)에게 위임된 권한

악의적 구현의 예로는 도메인에서 **elevated permissions**을 가진 공격자가 기본 **`User`** certificate template에 대해 **`WriteOwner`** 권한을 추가하고, 그 권한의 주체(principal)를 자신으로 설정하는 경우가 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유권을 자신으로 변경합니다. 그 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면, 요청 시 Subject Alternative Name을 제공할 수 있게 됩니다. 이후 공격자는 해당 **template**으로 **enroll**하여 대체 이름으로 도메인 관리자(domain administrator) 이름을 선택하고, 획득한 인증서를 DA로서의 인증에 사용할 수 있습니다.

장기적인 도메인 persistence를 위해 공격자가 설정할 수 있는 실무적 옵션들(전체 세부사항 및 탐지에 대한 내용은 {{#ref}}domain-escalation.md{{#endref}} 참조):

- 요청자(requesters)로부터 SAN을 허용하는 CA 정책 플래그(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이는 ESC1 유사 경로를 계속 악용 가능하게 합니다.
- 인증에 사용 가능한 발급을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- 방어자가 정리하려 할 때 rogue issuer를 지속적으로 재도입하기 위해 `NTAuthCertificates` 객체 또는 CA 컨테이너를 제어.

> [!TIP]
> KB5014754 이후 강화된 환경에서는 이러한 잘못된 구성에 명시적 강력 매핑(`altSecurityIdentities`)을 결합하면, DC가 강력한 매핑을 적용하더라도 발급되거나 위조된 인증서가 계속 사용 가능하도록 보장됩니다.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
