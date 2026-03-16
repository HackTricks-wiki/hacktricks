# AD 인증서

{{#include ../../banners/hacktricks-training.md}}

## 소개

### 인증서의 구성 요소

- **Subject**: 인증서의 소유자를 나타냅니다.
- **Public Key**: 개인 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **Validity Period**: **NotBefore** 및 **NotAfter** 날짜로 정의되는 인증서의 유효 기간입니다.
- 고유한 **Serial Number**: Certificate Authority(CA)가 부여하는 각 인증서를 식별하는 번호입니다.
- **Issuer**: 인증서를 발행한 CA를 가리킵니다.
- **SubjectAlternativeName**: 주체에 대한 추가 이름을 허용하여 식별 유연성을 제공합니다.
- **Basic Constraints**: 인증서가 CA용인지 최종 엔터티용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**: OID(Object Identifiers)를 통해 코드 서명, 이메일 암호화 등 인증서의 특정 용도를 명시합니다.
- **Signature Algorithm**: 인증서 서명 방식입니다.
- **Signature**: 발급자의 개인 키로 생성된 서명으로 인증서의 진위성을 보장합니다.

### 특별 고려사항

- **Subject Alternative Names (SANs)**는 인증서가 여러 식별자에 적용되도록 확장하여, 여러 도메인을 가진 서버에서 중요합니다. SAN 사양을 공격자가 조작해 스푸핑할 위험을 막기 위해 안전한 발급 프로세스가 필수적입니다.

### Active Directory(AD)의 Certificate Authorities(CAs)

AD CS는 포리스트 내에서 지정된 컨테이너들을 통해 CA 인증서를 인식하며, 각 컨테이너는 고유한 역할을 수행합니다:

- **Certification Authorities** 컨테이너는 신뢰된 루트 CA 인증서를 보관합니다.
- **Enrolment Services** 컨테이너는 Enterprise CAs와 해당 인증서 템플릿을 상세히 기록합니다.
- **NTAuthCertificates** 객체는 AD 인증에 허용된 CA 인증서를 포함합니다.
- **AIA (Authority Information Access)** 컨테이너는 중간 CA 및 크로스 CA 인증서를 통해 인증서 체인 검증을 지원합니다.

### 인증서 획득: 클라이언트 인증서 요청 흐름

1. 클라이언트가 Enterprise CA를 찾으면서 요청 프로세스가 시작됩니다.
2. 공개-비공개 키 쌍을 생성한 후 공개 키와 기타 정보를 포함한 CSR을 만듭니다.
3. CA는 사용 가능한 인증서 템플릿과 CSR을 비교하여 템플릿 권한에 따라 인증서를 발급할지를 결정합니다.
4. 승인되면 CA는 자신의 개인 키로 인증서에 서명하여 클라이언트에 반환합니다.

### 인증서 템플릿

AD 내에서 정의된 템플릿은 발급 설정과 권한을 개요하며, 허용된 EKU와 등록 또는 수정 권한 등을 포함해 인증서 서비스 접근 관리를 위해 중요합니다.

템플릿 스키마 버전이 중요합니다. 레거시 **v1** 템플릿(예: 내장 **WebServer** 템플릿)은 여러 현대적 강제 제어가 없습니다. **ESC15/EKUwu** 연구는 **v1 템플릿**에서 요청자가 CSR에 **Application Policies/EKUs**를 삽입하면 템플릿에 구성된 EKU보다 우선시되어, enrollment 권한만으로도 client-auth, enrollment agent, 또는 code-signing 인증서를 만들 수 있음을 보였습니다. 따라서 **v2/v3 템플릿**을 선호하고, v1 기본값을 제거하거나 대체하며, EKU를 의도된 목적에 맞게 엄격히 범위 지정하세요.

## 인증서 등록(Enrollment)

인증서 등록 프로세스는 관리자가 **인증서 템플릿을 생성**하면 시작되며, Enterprise Certificate Authority(CA)가 해당 템플릿을 **게시(publish)** 합니다. 이렇게 하면 템플릿이 클라이언트 등록에 사용 가능해지며, 이는 템플릿 이름을 Active Directory 객체의 `certificatetemplates` 필드에 추가하여 이루어집니다.

클라이언트가 인증서를 요청하려면 **enrollment rights**가 부여되어야 합니다. 이러한 권한은 인증서 템플릿과 Enterprise CA 자체의 보안 설명자(security descriptor)에 정의됩니다. 요청이 성공하려면 두 위치 모두에서 권한이 부여되어야 합니다.

### 템플릿 등록 권한

이 권한들은 ACE(Access Control Entries)를 통해 지정되며, 다음과 같은 권한을 포함합니다:

- **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** 권한(각각 특정 GUID와 연결됨).
- **ExtendedRights**: 모든 확장 권한 허용.
- **FullControl/GenericAll**: 템플릿에 대한 전체 제어 허용.

### Enterprise CA 등록 권한

CA의 권한은 Certificate Authority 관리 콘솔에서 접근 가능한 보안 설명자에 명시됩니다. 일부 설정은 저권한 사용자가 원격으로 접근할 수 있게 허용하는데, 이는 보안상 우려가 될 수 있습니다.

### 추가 발급 제어

다음과 같은 추가 제어가 적용될 수 있습니다:

- **Manager Approval**: 요청을 보류 상태로 두고 인증서 매니저의 승인을 요구합니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 서명의 수와 필요한 Application Policy OID를 지정합니다.

### 인증서 요청 방법

인증서는 다음을 통해 요청할 수 있습니다:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM 인터페이스 사용.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes 또는 TCP/IP를 통해.
3. **certificate enrollment web interface**, Certificate Authority Web Enrollment 역할 설치 시 사용.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) 서비스와 함께.
5. 네트워크 장치용 **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) 사용.

Windows 사용자는 GUI(`certmgr.msc` 또는 `certlm.msc`) 또는 명령줄 도구(`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)로도 인증서를 요청할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 인증서 인증

Active Directory (AD)는 인증서 인증을 지원하며 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용합니다.

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서는 사용자가 Ticket Granting Ticket (TGT)을 요청할 때 해당 요청이 사용자의 인증서에 있는 **private key**로 서명됩니다. 이 요청은 도메인 컨트롤러에서 인증서의 **유효성**, **경로**, **해지 상태** 등을 포함한 여러 검증을 받습니다. 검증에는 또한 인증서가 신뢰할 수 있는 출처에서 발급되었는지 확인하고 발행자가 **NTAUTH certificate store**에 존재하는지 확인하는 과정이 포함됩니다. 검증에 성공하면 TGT가 발급됩니다. AD에서 찾을 수 있는 **`NTAuthCertificates`** 객체는 다음 위치에 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
인증서 인증에서 신뢰를 확립하는 데 중심적이다.

### Secure Channel (Schannel) 인증

Schannel은 TLS/SSL 연결을 보호하며, 핸드셰이크 과정에서 클라이언트가 인증서를 제시하고 해당 인증서가 성공적으로 검증되면 접근이 허가된다. 인증서를 AD 계정에 매핑하는 방법으로는 Kerberos의 **S4U2Self** 기능이나 인증서의 **Subject Alternative Name (SAN)** 등 여러 방법이 있다.

### AD 인증서 서비스 열거

AD의 인증서 서비스는 LDAP 쿼리를 통해 열거할 수 있으며, 이를 통해 **Enterprise Certificate Authorities (CAs)** 및 해당 구성 정보가 드러난다. 이는 특수 권한 없이 도메인 인증된 사용자라면 누구나 접근할 수 있다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)**와 같은 도구들이 AD CS 환경에서의 열거 및 취약성 평가에 사용된다.

이 도구들을 사용하기 위한 명령 예시는 다음과 같다:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## 최근 취약점 및 보안 업데이트 (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | 패치는 **May 10 2022** 보안 업데이트에 포함되어 있습니다. **KB5014754**를 통해 감사 및 strong-mapping 제어가 도입되었으며, 환경은 이제 *Full Enforcement* 모드여야 합니다.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | 공개 PoC는 제한적이지만, 취약한 IIS 구성요소가 내부에 노출되는 경우가 많습니다. **July 2023** Patch Tuesday 기준으로 패치되었습니다.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | **November 12, 2024** 기준으로 패치되었습니다. v1 템플릿(예: 기본 WebServer)을 교체하거나 supersede하고, EKU를 의도에 맞게 제한하며 enrollment 권한을 제한하세요. |

### Microsoft hardening timeline (KB5014754)

Microsoft는 Kerberos certificate authentication을 약한 암시적 매핑에서 분리하기 위해 세 단계 롤아웃(Compatibility → Audit → Enforcement)을 도입했습니다. **February 11 2025** 기준으로 `StrongCertificateBindingEnforcement` 레지스트리 값이 설정되지 않은 경우 도메인 컨트롤러는 자동으로 **Full Enforcement**로 전환됩니다. 관리자는 다음을 수행해야 합니다:

1. 모든 DC 및 AD CS 서버를 패치하세요 (May 2022 이후 패치).
2. *Audit* 단계 동안 약한 매핑을 모니터링하기 위해 Event ID 39/41을 확인하세요.
3. 새로운 **SID extension**이 포함된 client-auth 인증서를 재발급하거나 2025년 2월 이전에 강력한 수동 매핑을 구성하세요.

---

## 탐지 및 강화 권장사항

* **Defender for Identity AD CS sensor (2023-2024)** 는 ESC1-ESC8/ESC11에 대한 자세한 자세(posture) 평가를 제공하고, *“Domain-controller certificate issuance for a non-DC”* (ESC8) 및 *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) 같은 실시간 경고를 생성합니다. 이러한 탐지를 활용하려면 모든 AD CS 서버에 센서를 배포하세요.
* 모든 템플릿에서 **“Supply in the request”** 옵션을 비활성화하거나 엄격히 범위를 제한하고; 명시적으로 정의된 SAN/EKU 값을 선호하세요.
* 템플릿에서 **Any Purpose** 또는 **No EKU**를 반드시 필요한 경우가 아니면 제거하세요 (ESC2 시나리오 대응).
* 민감한 템플릿(예: WebServer / CodeSigning)에 대해서는 **관리자 승인** 또는 전용 Enrollment Agent 워크플로우를 요구하세요.
* web enrollment (`certsrv`) 및 CES/NDES 엔드포인트를 신뢰된 네트워크로 제한하거나 client-certificate authentication 뒤에 두세요.
* ESC11 (RPC relay)을 완화하려면 RPC enrollment 암호화 적용을 사용하세요 (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). 이 플래그는 **기본적으로 활성화되어 있음**이지만 레거시 클라이언트 때문에 종종 비활성화되어 릴레이 위험이 다시 열립니다.
* **IIS-based enrollment endpoints**(CES/Certsrv)를 보호하세요: 가능한 경우 NTLM을 비활성화하거나 ESC8 릴레이를 차단하기 위해 HTTPS + Extended Protection을 요구하세요.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
