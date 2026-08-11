# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- 인증서의 **Subject**는 소유자를 나타냅니다.
- **Public Key**는 비공개로 보관되는 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **Validity Period**는 **NotBefore** 및 **NotAfter** 날짜로 정의되며, 인증서의 유효 기간을 나타냅니다.
- Certificate Authority (CA)가 제공하는 고유한 **Serial Number**는 각 인증서를 식별합니다.
- **Issuer**는 인증서를 발급한 CA를 나타냅니다.
- **SubjectAlternativeName**을 사용하면 Subject에 추가 이름을 지정할 수 있어 식별 유연성이 향상됩니다.
- **Basic Constraints**는 인증서가 CA용인지 최종 엔터티용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 Object Identifiers (OIDs)를 통해 코드 서명이나 이메일 암호화와 같은 인증서의 구체적인 용도를 지정합니다.
- **Signature Algorithm**은 인증서 서명에 사용되는 방법을 지정합니다.
- Issuer의 비공개 키로 생성되는 **Signature**는 인증서의 진위를 보장합니다.<sup>[[1]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)**는 인증서를 여러 ID에 적용할 수 있도록 확장하며, 여러 도메인을 사용하는 서버에 특히 중요합니다. 공격자가 SAN 사양을 조작하여 사칭하는 위험을 방지하려면 안전한 발급 프로세스가 필수적입니다.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS는 지정된 컨테이너를 통해 AD forest의 CA 인증서를 인식하며, 각 컨테이너는 고유한 역할을 수행합니다.<sup>[[1]](#references)</sup>

- **Certification Authorities** 컨테이너에는 신뢰할 수 있는 root CA 인증서가 저장됩니다.
- **Enrolment Services** 컨테이너에는 Enterprise CA와 해당 인증서 템플릿에 대한 정보가 저장됩니다.
- **NTAuthCertificates** object에는 AD 인증에 사용할 수 있도록 권한이 부여된 CA 인증서가 포함됩니다.
- **AIA (Authority Information Access)** 컨테이너는 intermediate 및 cross CA 인증서를 사용하여 인증서 체인을 검증할 수 있도록 합니다.

### Certificate Acquisition: Client Certificate Request Flow

1. 요청 프로세스는 client가 Enterprise CA를 찾는 것에서 시작됩니다.
2. public-private key pair를 생성한 후 public key와 기타 세부 정보가 포함된 CSR이 생성됩니다.
3. CA는 사용 가능한 인증서 템플릿을 기준으로 CSR을 평가하고, 템플릿의 권한에 따라 인증서를 발급합니다.
4. 승인되면 CA는 비공개 키로 인증서에 서명하고 이를 client에게 반환합니다.<sup>[[1]](#references)</sup>

### Certificate Templates

AD 내에서 정의되는 이러한 템플릿은 허용되는 EKU와 enrollment 또는 수정 권한을 포함하여 인증서 발급을 위한 설정과 권한을 지정하며, 인증서 서비스에 대한 access 관리에 중요합니다.<sup>[[1]](#references)</sup>

## Certificate Enrollment

인증서 enrollment 프로세스는 관리자가 **certificate template을 생성**하는 것으로 시작되며, 이후 Enterprise Certificate Authority (CA)가 이를 **게시**합니다. 이를 통해 client가 해당 템플릿을 사용해 enrollment할 수 있으며, Active Directory object의 `certificatetemplates` field에 템플릿 이름을 추가하여 이 작업을 수행합니다.<sup>[[1]](#references)</sup>

client가 인증서를 요청하려면 **enrollment rights**가 부여되어야 합니다. 이러한 권한은 certificate template과 Enterprise CA 자체의 security descriptor에 정의됩니다. 요청이 성공하려면 두 위치 모두에서 권한이 부여되어야 합니다.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

이러한 권한은 다음과 같은 권한을 지정하는 Access Control Entries (ACEs)를 통해 설정됩니다.<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** rights는 각각 특정 GUID와 연결됩니다.
- **ExtendedRights**는 모든 extended permissions를 허용합니다.
- **FullControl/GenericAll**은 템플릿에 대한 완전한 control을 제공합니다.

### Enterprise CA Enrollment Rights

CA의 권한은 Certificate Authority management console을 통해 확인할 수 있는 security descriptor에 정의됩니다. 일부 설정에서는 low-privileged user에게 remote access까지 허용하므로 security concern이 될 수 있습니다.<sup>[[1]](#references)</sup>

### Additional Issuance Controls

다음과 같은 특정 control이 적용될 수 있습니다.<sup>[[1]](#references)</sup>

- **Manager Approval**: certificate manager가 승인할 때까지 요청을 pending 상태로 유지합니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 서명 수와 필요한 Application Policy OIDs를 지정합니다.

### Methods to Request Certificates

인증서는 다음 방법으로 요청할 수 있습니다.<sup>[[1]](#references)</sup>

1. DCOM interface를 사용하는 **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. named pipe 또는 TCP/IP를 통한 **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment role이 설치된 **certificate enrollment web interface**.
4. Certificate Enrollment Policy (CEP) service와 함께 사용하는 **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP)을 사용하는 network device용 **Network Device Enrollment Service** (NDES).

Windows user는 GUI (`certmgr.msc` 또는 `certlm.msc`)나 command-line tool (`certreq.exe` 또는 PowerShell의 `Get-Certificate` command)을 통해서도 인증서를 요청할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 인증서 인증

Active Directory (AD)는 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용하여 인증서 인증을 지원합니다.<sup>[[1]](#references)</sup>

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서 사용자가 Ticket Granting Ticket (TGT)을 요청할 때, 사용자의 인증서 **private key**를 사용하여 요청에 서명합니다. 이 요청은 도메인 컨트롤러에서 인증서의 **유효성**, **경로**, **취소 상태**를 포함한 여러 검증을 거칩니다. 또한 인증서가 신뢰할 수 있는 출처에서 발급되었는지 확인하고 발급자가 **NTAUTH certificate store**에 존재하는지 검증합니다. 검증이 성공하면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** 객체는 다음 위치에 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
인증서 인증에 대한 신뢰를 설정하는 데 핵심적인 역할을 합니다.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel은 안전한 TLS/SSL 연결을 지원하며, 핸드셰이크 과정에서 클라이언트가 인증서를 제시하고, 인증서가 성공적으로 검증되면 액세스 권한이 부여됩니다.<sup>[[2]](#references)</sup> 인증서를 AD 계정에 매핑하는 과정에는 Kerberos의 **S4U2Self** 기능이나 인증서의 **Subject Alternative Name (SAN)** 등이 사용될 수 있습니다.<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD의 certificate services는 LDAP 쿼리를 통해 열거할 수 있으며, **Enterprise Certificate Authorities (CAs)** 및 해당 구성에 대한 정보를 확인할 수 있습니다. 이는 특별한 권한이 없는 모든 domain-authenticated user가 사용할 수 있습니다.<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)**와 같은 도구는 AD CS 환경에서 열거 및 취약점 평가에 사용됩니다.<sup>[[3]](#references)</sup>

이러한 도구를 사용하는 명령은 다음과 같습니다:
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
Rubeus는 password-protected PFX certificate를 사용하여 PKINIT authentication을 수행하고 TGT를 요청할 수도 있습니다. 선택적 `/getcredentials` switch는 U2U service ticket을 요청하고 account NT hash 복구를 시도합니다:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Active Directory Certificate Services 악용](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [SSL/TLS 클라이언트 인증이란 무엇이며 어떻게 작동하는가?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
