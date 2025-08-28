# AD 인증서

{{#include ../../../banners/hacktricks-training.md}}

## 소개

### 인증서의 구성 요소

- 인증서의 **Subject**는 인증서 소유자를 나타냅니다.
- **Public Key**는 개인 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **Validity Period**는 **NotBefore**와 **NotAfter** 날짜로 정의되며 인증서의 유효 기간을 나타냅니다.
- CA에서 부여하는 고유한 **Serial Number**는 각 인증서를 식별합니다.
- **Issuer**는 인증서를 발급한 CA를 의미합니다.
- **SubjectAlternativeName**은 추가적인 주체 이름을 허용하여 식별 유연성을 높입니다.
- **Basic Constraints**는 인증서가 CA용인지 엔드 엔터티용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 OID를 통해 코드 서명이나 이메일 암호화 같은 인증서의 특정 용도를 구분합니다.
- **Signature Algorithm**은 인증서 서명 방식을 지정합니다.
- **Signature**는 발급자의 개인 키로 만들어져 인증서의 진위를 보장합니다.

### 특수 고려사항

- **Subject Alternative Names (SANs)**는 단일 인증서를 여러 신원에 적용할 수 있게 하며, 다중 도메인을 가진 서버에 중요합니다. SAN 사양을 변조하여 위장 위험을 초래하지 않도록 발급 과정의 보안이 필수적입니다.

### Active Directory(AD)의 Certificate Authorities (CAs)

AD CS는 AD 포리스트 내에서 지정된 컨테이너들을 통해 CA 인증서를 인식하며, 각 컨테이너는 고유한 역할을 합니다:

- **Certification Authorities** 컨테이너는 신뢰된 루트 CA 인증서를 보관합니다.
- **Enrolment Services** 컨테이너는 Enterprise CAs와 그들의 certificate templates 정보를 포함합니다.
- **NTAuthCertificates** 객체는 AD 인증에 허용된 CA 인증서를 포함합니다.
- **AIA (Authority Information Access)** 컨테이너는 중간 CA 및 cross CA 인증서를 통해 인증서 체인 검증을 지원합니다.

### 인증서 획득: 클라이언트 인증서 요청 흐름

1. 프로세스는 클라이언트가 Enterprise CA를 찾는 것으로 시작합니다.
2. 공개-개인 키 쌍을 생성한 후 CSR이 만들어지며, 여기에는 public key 및 기타 세부 정보가 포함됩니다.
3. CA는 사용 가능한 certificate templates와 CSR을 대조하여 템플릿 권한에 따라 인증서를 발급할지 평가합니다.
4. 승인이 되면 CA는 개인 키로 인증서에 서명하고 이를 클라이언트에 반환합니다.

### Certificate Templates

AD 내에서 정의된 이 템플릿들은 인증서 발급 설정과 권한(허용된 EKU, 등록 또는 수정 권한 등)을 규정하며, 인증서 서비스 접근 관리를 위해 중요합니다.

## 인증서 등록(Enrollment)

인증서 등록 프로세스는 관리자가 **certificate template을 생성**하고 Enterprise Certificate Authority(CA)가 이를 **published** 함으로써 시작됩니다. 이렇게 되면 템플릿은 클라이언트 등록에 이용 가능해지며, Active Directory 객체의 `certificatetemplates` 필드에 템플릿 이름을 추가하여 달성됩니다.

클라이언트가 인증서를 요청하려면 **enrollment rights**가 부여되어야 합니다. 이 권한들은 certificate template과 Enterprise CA 자체의 보안 설명자(security descriptor)에 의해 정의됩니다. 요청이 성공하려면 두 위치 모두에서 권한이 부여되어야 합니다.

### 템플릿 등록 권한

이 권한들은 ACEs(Access Control Entries)를 통해 지정되며, 다음과 같은 권한들을 포함합니다:

- 특정 GUID와 연관된 **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** 권한.
- 모든 확장 권한을 허용하는 **ExtendedRights**.
- 템플릿에 대한 전체 제어를 허용하는 **FullControl/GenericAll**.

### Enterprise CA 등록 권한

CA의 권한은 Certificate Authority 관리 콘솔에서 접근 가능한 보안 설명자에 명시됩니다. 일부 설정은 저권한 사용자가 원격으로 접근할 수 있게 허용할 수 있어 보안상 우려가 될 수 있습니다.

### 추가 발급 제어 사항

일부 제어는 다음과 같이 적용될 수 있습니다:

- **Manager Approval**: 요청을 보류 상태로 두어 certificate manager의 승인을 받을 때까지 대기시킵니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 서명 수와 필요한 Application Policy OID를 지정합니다.

### 인증서 요청 방법

인증서는 다음 방법들로 요청할 수 있습니다:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM 인터페이스를 통해.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes 또는 TCP/IP를 통해.
3. Certificate Authority Web Enrollment 역할이 설치된 **certificate enrollment web interface**.
4. **Certificate Enrollment Service** (CES)와 Certificate Enrollment Policy (CEP) 서비스를 함께 이용.
5. 네트워크 장치를 위한 **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP)을 사용.

Windows 사용자는 또한 GUI(`certmgr.msc` 또는 `certlm.msc`)나 커맨드라인 도구(`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)를 통해 인증서를 요청할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD)는 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용하여 인증서 기반 인증을 지원합니다.

### Kerberos Authentication Process

Kerberos 인증 프로세스에서 사용자의 Ticket Granting Ticket (TGT) 요청은 사용자의 인증서에 있는 **private key**로 서명됩니다. 이 요청은 도메인 컨트롤러에서 인증서의 **validity**, **path**, **revocation status** 등을 포함한 여러 검증을 거칩니다. 또한 인증서가 신뢰할 수 있는 출처에서 왔는지와 발급자의 존재가 **NTAUTH certificate store**에 있는지 확인하는 검증도 수행됩니다. 검증이 성공하면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** 객체는 다음 위치에서 찾을 수 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
인증서 인증을 위한 신뢰 구축에 중심적이다.

### Secure Channel (Schannel) 인증

Schannel은 TLS/SSL 연결을 보호하며, 핸드셰이크 동안 클라이언트가 인증서를 제시하고 해당 인증서가 성공적으로 검증되면 액세스를 허가한다. 인증서를 AD 계정에 매핑하는 과정에는 Kerberos의 **S4U2Self** 기능 또는 인증서의 **Subject Alternative Name (SAN)** 등 여러 방법이 포함될 수 있다.

### AD Certificate Services 열거

AD의 certificate services는 LDAP 쿼리를 통해 열거할 수 있으며, **Enterprise Certificate Authorities (CAs)** 및 그 구성 정보를 드러낸다. 이는 특권 없이 도메인 인증을 받은 모든 사용자가 접근할 수 있다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)** 같은 도구는 AD CS 환경에서 열거 및 취약점 평가에 사용된다.

이 도구들을 사용하는 명령은 다음과 같다:
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
