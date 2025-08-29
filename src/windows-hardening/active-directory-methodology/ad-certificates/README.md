# AD 인증서

{{#include ../../../banners/hacktricks-training.md}}

## 소개

### 인증서 구성 요소

- 인증서의 **Subject**는 소유자를 나타냅니다.
- **Public Key**는 개인 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **유효 기간**은 **NotBefore** 및 **NotAfter** 날짜로 정의되며 인증서의 유효 기간을 표시합니다.
- 고유한 **Serial Number**는 Certificate Authority(CA)가 제공하며 각 인증서를 식별합니다.
- **Issuer**는 인증서를 발행한 CA를 가리킵니다.
- **SubjectAlternativeName**은 subject에 대한 추가 이름을 허용하여 식별 유연성을 제공합니다.
- **Basic Constraints**는 인증서가 CA용인지 엔드 엔터티용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 Object Identifiers(OIDs)를 통해 코드 서명이나 이메일 암호화와 같은 인증서의 특정 용도를 구분합니다.
- **Signature Algorithm**은 인증서를 서명하는 방법을 지정합니다.
- **Signature**는 발행자의 개인 키로 생성되어 인증서의 진위를 보장합니다.

### 특별 고려 사항

- **Subject Alternative Names (SANs)**는 하나의 인증서를 여러 정체성에 적용할 수 있게 하여, 여러 도메인을 가진 서버에 특히 중요합니다. SAN 규격을 조작해 사칭하는 공격을 방지하려면 안전한 발급 절차가 필수적입니다.

### Active Directory(AD)의 Certificate Authorities (CAs)

AD CS는 지정된 컨테이너를 통해 AD 포리스트에서 CA 인증서를 인식하며, 각 컨테이너는 고유한 역할을 합니다:

- **Certification Authorities** 컨테이너에는 신뢰된 루트 CA 인증서가 저장됩니다.
- **Enrolment Services** 컨테이너에는 Enterprise CAs 및 해당 인증서 템플릿에 대한 정보가 포함됩니다.
- **NTAuthCertificates** 객체에는 AD 인증에 허용된 CA 인증서가 포함됩니다.
- **AIA (Authority Information Access)** 컨테이너는 중간 CA 및 교차 CA 인증서와 함께 인증서 체인 검증을 돕습니다.

### 인증서 획득: 클라이언트 인증서 요청 흐름

1. 클라이언트가 Enterprise CA를 찾는 것으로 요청 프로세스가 시작됩니다.
2. 공개-개인 키 쌍을 생성한 후 공개 키와 기타 세부 정보를 포함한 CSR이 작성됩니다.
3. CA는 사용 가능한 인증서 템플릿에 대해 CSR을 평가하고, 템플릿 권한에 따라 인증서를 발급합니다.
4. 승인되면 CA는 자신의 개인 키로 인증서에 서명하여 클라이언트에게 반환합니다.

### 인증서 템플릿

AD 내에서 정의되는 이 템플릿은 인증서 발급 설정과 권한을 규정하며, 허용된 EKU, 등록(enrollment) 또는 수정 권한 등 인증서 서비스 접근 관리를 위해 중요합니다.

## 인증서 등록

인증서 등록 프로세스는 관리자가 **인증서 템플릿을 생성**하면 시작되고, 그 템플릿은 Enterprise Certificate Authority(CA)에 의해 **게시**됩니다. 이렇게 하면 템플릿이 클라이언트 등록에 사용 가능해지며, 이는 Active Directory 객체의 `certificatetemplates` 필드에 템플릿 이름을 추가하여 이루어집니다.

클라이언트가 인증서를 요청하려면 **등록 권한(enrollment rights)** 이 부여되어야 합니다. 이러한 권한은 인증서 템플릿 및 Enterprise CA 자체의 보안 설명자(security descriptor)에 의해 정의됩니다. 요청이 성공하려면 두 위치 모두에 권한이 부여되어야 합니다.

### 템플릿 등록 권한

이 권한들은 Access Control Entries(ACEs)를 통해 지정되며, 다음과 같은 권한들을 상세히 기술합니다:

- **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** 권한(각각 특정 GUID와 연관)
- **ExtendedRights**, 모든 확장 권한을 허용
- **FullControl/GenericAll**, 템플릿에 대한 전체 제어 권한 제공

### Enterprise CA 등록 권한

CA의 권한은 Certificate Authority 관리 콘솔에서 접근 가능한 보안 설명자에 명시됩니다. 일부 설정은 낮은 권한의 사용자에게 원격 접근을 허용할 수도 있어 보안상 우려가 될 수 있습니다.

### 추가 발급 제어

다음과 같은 제어가 적용될 수 있습니다:

- **Manager Approval**: 요청을 대기(pending) 상태로 두고 인증서 매니저의 승인이 있을 때까지 보류합니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 서명 수와 요구되는 Application Policy OID를 지정합니다.

### 인증서 요청 방법

인증서는 다음을 통해 요청할 수 있습니다:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM 인터페이스 사용.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes 또는 TCP/IP 통해.
3. **certificate enrollment web interface**, Certificate Authority Web Enrollment 역할이 설치된 경우.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) 서비스와 함께 사용.
5. 네트워크 장치를 위한 **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) 사용.

Windows 사용자는 GUI(`certmgr.msc` 또는 `certlm.msc`)나 커맨드라인 도구(`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)를 통해서도 인증서를 요청할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 인증서 인증

Active Directory (AD) supports certificate authentication, primarily utilizing **Kerberos** and **Secure Channel (Schannel)** protocols.

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서 사용자의 Ticket Granting Ticket (TGT) 요청은 사용자의 인증서에 있는 **private key**로 서명된다. 이 요청은 도메인 컨트롤러에서 인증서의 **validity**, **path**, **revocation status** 등을 포함한 여러 검증을 거친다. 검증에는 또한 인증서가 신뢰할 수 있는 출처인지 확인하고 발급자가 **NTAUTH certificate store**에 존재하는지도 확인하는 절차가 포함된다. 검증에 성공하면 TGT가 발급된다. AD의 **`NTAuthCertificates`** 객체는 다음 위치에 있다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
인증서 인증의 신뢰를 구축하는 데 중심적이다.

### Secure Channel (Schannel) Authentication

Schannel은 안전한 TLS/SSL 연결을 지원하며, 핸드셰이크 동안 클라이언트가 인증서를 제시하고 해당 인증서가 성공적으로 검증되면 접근이 허용됩니다. 인증서를 AD 계정에 매핑하는 방법에는 Kerberos의 **S4U2Self** 기능이나 인증서의 **Subject Alternative Name (SAN)** 등 여러 방법이 있을 수 있습니다.

### AD Certificate Services Enumeration

AD의 인증서 서비스는 LDAP 쿼리를 통해 열거할 수 있으며, **Enterprise Certificate Authorities (CAs)** 및 그 구성 정보를 드러냅니다. 이는 특권 없이 도메인에 인증된 모든 사용자가 접근할 수 있습니다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)** 같은 도구는 AD CS 환경에서 열거 및 취약점 평가에 사용됩니다.

Commands for using these tools include:
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
## 참고 자료

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
